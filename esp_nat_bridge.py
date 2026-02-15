#!/usr/bin/env python3
"""
ESP32 NAT Router MCP Bridge

MCP server that controls an ESP32 NAT Router via its remote console (telnet/TCP).
Uses fastmcp and telnetlib3.

Usage:
    python esp_nat_bridge.py                          # stdio mode (for MCP clients)
    python esp_nat_bridge.py --transport streamable-http --port 8000  # HTTP mode

Environment variables:
    ESP_NAT_HOST     - Router IP address (default: 192.168.4.1)
    ESP_NAT_PORT     - Remote console TCP port (default: 2323)
    ESP_NAT_PASSWORD - Remote console password (default: empty)
"""

import asyncio
import os
import re
import shutil
import struct
import tempfile
from contextlib import asynccontextmanager
from typing import Optional

import telnetlib3
from fastmcp import FastMCP, Context

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

ESP_HOST = os.environ.get("ESP_NAT_HOST", "192.168.4.1")
ESP_PORT = int(os.environ.get("ESP_NAT_PORT", "2323"))
ESP_PASSWORD = os.environ.get("ESP_NAT_PASSWORD", "")

COMMAND_TIMEOUT = 10  # seconds to wait for command output
CONNECT_TIMEOUT = 10  # seconds to wait for TCP connection
PCAP_PORT = 19000     # ESP32 PCAP streaming TCP port

# ---------------------------------------------------------------------------
# Telnet connection manager
# ---------------------------------------------------------------------------


class RouterConnection:
    """Manages a persistent telnet connection to the ESP32 remote console."""

    def __init__(self, host: str, port: int, password: str):
        self.host = host
        self.port = port
        self.password = password
        self.reader: Optional[telnetlib3.TelnetReader] = None
        self.writer: Optional[telnetlib3.TelnetWriter] = None
        self._lock = asyncio.Lock()

    async def connect(self):
        """Establish telnet connection and authenticate if needed."""
        self.reader, self.writer = await asyncio.wait_for(
            telnetlib3.open_connection(self.host, self.port, encoding="utf-8"),
            timeout=CONNECT_TIMEOUT,
        )
        # Read the initial banner/prompt
        banner = await self._read_until_prompt(timeout=5)

        # If we see a password prompt, authenticate
        if "password" in banner.lower() or "Password" in banner:
            if not self.password:
                raise RuntimeError(
                    "Router requires a password but ESP_NAT_PASSWORD is not set"
                )
            self.writer.write(self.password + "\r\n")
            auth_response = await self._read_until_prompt(timeout=5)
            if "denied" in auth_response.lower() or "invalid" in auth_response.lower():
                raise RuntimeError("Authentication failed - check ESP_NAT_PASSWORD")

    async def disconnect(self):
        """Close the telnet connection."""
        if self.writer:
            try:
                self.writer.write("quit\r\n")
                self.writer.close()
            except Exception:
                pass
        self.reader = None
        self.writer = None

    async def _read_until_prompt(self, timeout: float = COMMAND_TIMEOUT) -> str:
        """Read data until we see the ESP32 command prompt or timeout."""
        buf = ""
        try:
            end_time = asyncio.get_event_loop().time() + timeout
            while asyncio.get_event_loop().time() < end_time:
                remaining = end_time - asyncio.get_event_loop().time()
                if remaining <= 0:
                    break
                try:
                    chunk = await asyncio.wait_for(
                        self.reader.read(4096), timeout=min(remaining, 1.0)
                    )
                except asyncio.TimeoutError:
                    # Check if we already have a complete response
                    if buf.strip() and (buf.rstrip().endswith(">") or buf.rstrip().endswith("#") or "\nesp32>" in buf or "\n> " in buf):
                        break
                    continue
                if not chunk:
                    break
                buf += chunk
                # The ESP32 console prompt is typically "esp32> " or just "> "
                if "esp32>" in buf or "\n> " in buf or buf.rstrip().endswith(">"):
                    break
        except asyncio.TimeoutError:
            pass
        return buf

    async def send_command(self, command: str) -> str:
        """Send a command and return the response text."""
        async with self._lock:
            if not self.writer or not self.reader:
                await self.connect()

            try:
                # Drain any pending data
                try:
                    while True:
                        chunk = await asyncio.wait_for(
                            self.reader.read(4096), timeout=0.2
                        )
                        if not chunk:
                            break
                except asyncio.TimeoutError:
                    pass

                self.writer.write(command + "\r\n")
                response = await self._read_until_prompt()

                # Strip the echoed command and the trailing prompt
                lines = response.splitlines()
                # Remove echo of the command
                if lines and command.strip() in lines[0]:
                    lines = lines[1:]
                # Remove trailing prompt line
                while lines and (
                    lines[-1].strip() in ("esp32>", ">", "")
                    or lines[-1].strip().endswith(">")
                ):
                    lines.pop()

                return "\n".join(lines).strip()
            except (ConnectionError, OSError, EOFError) as e:
                # Connection lost, try to reconnect once
                await self.disconnect()
                try:
                    await self.connect()
                    self.writer.write(command + "\r\n")
                    response = await self._read_until_prompt()
                    lines = response.splitlines()
                    if lines and command.strip() in lines[0]:
                        lines = lines[1:]
                    while lines and (
                        lines[-1].strip() in ("esp32>", ">", "")
                        or lines[-1].strip().endswith(">")
                    ):
                        lines.pop()
                    return "\n".join(lines).strip()
                except Exception:
                    raise RuntimeError(
                        f"Lost connection to router and reconnect failed: {e}"
                    )


# ---------------------------------------------------------------------------
# Global connection instance
# ---------------------------------------------------------------------------

_conn: Optional[RouterConnection] = None


def _get_conn() -> RouterConnection:
    global _conn
    if _conn is None:
        _conn = RouterConnection(ESP_HOST, ESP_PORT, ESP_PASSWORD)
    return _conn


@asynccontextmanager
async def lifespan(server):
    """Startup/shutdown lifecycle for the MCP server."""
    conn = _get_conn()
    try:
        await conn.connect()
    except Exception as e:
        print(f"Warning: initial connection failed ({e}), will retry on first command")
    yield
    await conn.disconnect()


# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------

mcp = FastMCP(
    "ESP32 NAT Router Bridge",
    instructions="Control an ESP32 NAT Router via its remote console (telnet/TCP)",
    lifespan=lifespan,
)


# ── Helpers ──────────────────────────────────────────────────────────────────

async def _cmd(command: str) -> str:
    """Send a raw command and return the cleaned output."""
    conn = _get_conn()
    return await conn.send_command(command)


def _require(value: Optional[str], name: str):
    if not value or not value.strip():
        raise ValueError(f"'{name}' is required")


# ═══════════════════════════════════════════════════════════════════════════
# STATUS & INFORMATION
# ═══════════════════════════════════════════════════════════════════════════


@mcp.tool()
async def show_status() -> str:
    """Show router status: connection state, uptime, IPs, connected clients, traffic stats, free heap."""
    return await _cmd("show status")


@mcp.tool()
async def show_config() -> str:
    """Show router configuration: AP/STA WiFi settings, static IP, enterprise auth, web UI state."""
    return await _cmd("show config")


@mcp.tool()
async def show_mappings() -> str:
    """Show DHCP pool, DHCP reservations, and port forwarding mappings."""
    return await _cmd("show mappings")


@mcp.tool()
async def show_acl() -> str:
    """Show all firewall ACL rules and hit statistics for all four lists."""
    return await _cmd("show acl")


@mcp.tool()
async def get_heap_info() -> str:
    """Get current free heap memory and the minimum free heap seen during runtime."""
    return await _cmd("heap")


@mcp.tool()
async def get_version() -> str:
    """Get ESP32 chip info, IDF version, and firmware details."""
    return await _cmd("version")


@mcp.tool()
async def get_tasks() -> str:
    """List all running FreeRTOS tasks with their status, priority, and stack high water mark."""
    return await _cmd("tasks")


@mcp.tool()
async def get_byte_counts() -> str:
    """Show STA interface byte counters (bytes sent and received)."""
    return await _cmd("bytes")


@mcp.tool()
async def reset_byte_counts() -> str:
    """Reset STA interface byte counters to zero."""
    return await _cmd("bytes reset")


@mcp.tool()
async def wifi_scan() -> str:
    """Scan for available WiFi networks. Returns SSID, RSSI, and security mode for each network found."""
    return await _cmd("scan")


# ═══════════════════════════════════════════════════════════════════════════
# WIFI STA (UPSTREAM) CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════


@mcp.tool()
async def set_sta(
    ssid: str,
    password: str = "",
    enterprise_username: str = "",
    enterprise_identity: str = "",
    eap_method: int = -1,
    ttls_phase2: int = -1,
    cert_bundle: int = -1,
    no_time_check: int = -1,
) -> str:
    """Set upstream WiFi (STA) credentials. Requires restart to take effect.

    Args:
        ssid: SSID of the upstream WiFi network.
        password: WiFi password (leave empty for open networks).
        enterprise_username: WPA2-Enterprise username (optional).
        enterprise_identity: WPA2-Enterprise identity (optional, defaults to username).
        eap_method: EAP method: 0=Auto, 1=PEAP, 2=TTLS, 3=TLS. -1 to skip.
        ttls_phase2: TTLS phase 2: 0=MSCHAPv2, 1=MSCHAP, 2=PAP, 3=CHAP. -1 to skip.
        cert_bundle: Use CA cert bundle: 0=no, 1=yes. -1 to skip.
        no_time_check: Skip cert time check: 0=no, 1=yes. -1 to skip.
    """
    _require(ssid, "ssid")
    cmd = f"set_sta {ssid} {password}"
    if enterprise_username:
        cmd += f" -u {enterprise_username}"
    if enterprise_identity:
        cmd += f" -a {enterprise_identity}"
    if eap_method >= 0:
        cmd += f" -e {eap_method}"
    if ttls_phase2 >= 0:
        cmd += f" -p {ttls_phase2}"
    if cert_bundle >= 0:
        cmd += f" -c {cert_bundle}"
    if no_time_check >= 0:
        cmd += f" -t {no_time_check}"
    return await _cmd(cmd)


@mcp.tool()
async def set_sta_static(ip: str, subnet: str, gateway: str) -> str:
    """Set a static IP address for the STA (upstream) interface. Requires restart.

    Args:
        ip: Static IP address (e.g. "192.168.0.100").
        subnet: Subnet mask (e.g. "255.255.255.0").
        gateway: Gateway address (e.g. "192.168.0.1").
    """
    _require(ip, "ip")
    _require(subnet, "subnet")
    _require(gateway, "gateway")
    return await _cmd(f"set_sta_static {ip} {subnet} {gateway}")


@mcp.tool()
async def set_sta_mac(mac: str) -> str:
    """Set the MAC address of the STA interface. Requires restart.

    Args:
        mac: MAC address in format "AA:BB:CC:DD:EE:FF".
    """
    _require(mac, "mac")
    octets = re.split(r"[:\-]", mac)
    if len(octets) != 6:
        raise ValueError("MAC address must have 6 octets (AA:BB:CC:DD:EE:FF)")
    # Convert hex strings to decimal for the CLI command
    dec_octets = " ".join(str(int(o, 16)) for o in octets)
    return await _cmd(f"set_sta_mac {dec_octets}")


# ═══════════════════════════════════════════════════════════════════════════
# WIFI AP (ACCESS POINT) CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════


@mcp.tool()
async def set_ap(ssid: str, password: str = "") -> str:
    """Set the access point SSID and password. Requires restart.

    Args:
        ssid: SSID for the ESP32 access point.
        password: AP password (empty for open network, min 8 chars for WPA2).
    """
    _require(ssid, "ssid")
    return await _cmd(f"set_ap {ssid} {password}")


@mcp.tool()
async def set_ap_ip(ip: str) -> str:
    """Set the IP address of the AP interface (default: 192.168.4.1). Requires restart.
    Warning: changing this will delete all DHCP reservations and port mappings.

    Args:
        ip: IP address for the AP interface (e.g. "192.168.4.1").
    """
    _require(ip, "ip")
    return await _cmd(f"set_ap_ip {ip}")


@mcp.tool()
async def set_ap_mac(mac: str) -> str:
    """Set the MAC address of the AP interface. Requires restart.

    Args:
        mac: MAC address in format "AA:BB:CC:DD:EE:FF".
    """
    _require(mac, "mac")
    octets = re.split(r"[:\-]", mac)
    if len(octets) != 6:
        raise ValueError("MAC address must have 6 octets (AA:BB:CC:DD:EE:FF)")
    dec_octets = " ".join(str(int(o, 16)) for o in octets)
    return await _cmd(f"set_ap_mac {dec_octets}")


@mcp.tool()
async def set_ap_hidden(hidden: bool) -> str:
    """Hide or show the AP SSID in WiFi scans. Requires restart.

    Args:
        hidden: True to hide SSID, False to make it visible.
    """
    return await _cmd(f"set_ap_hidden {'on' if hidden else 'off'}")


# ═══════════════════════════════════════════════════════════════════════════
# DHCP RESERVATIONS
# ═══════════════════════════════════════════════════════════════════════════


@mcp.tool()
async def add_dhcp_reservation(mac: str, ip: str, name: str = "") -> str:
    """Add a DHCP reservation to assign a fixed IP to a MAC address.

    Args:
        mac: Device MAC address (format: AA:BB:CC:DD:EE:FF).
        ip: Reserved IP address (must be in the AP subnet DHCP pool).
        name: Optional friendly device name (used in ACL rules and display).
    """
    _require(mac, "mac")
    _require(ip, "ip")
    cmd = f"dhcp_reserve add {mac} {ip}"
    if name:
        cmd += f" -n {name}"
    return await _cmd(cmd)


@mcp.tool()
async def delete_dhcp_reservation(mac: str) -> str:
    """Delete a DHCP reservation by MAC address.

    Args:
        mac: Device MAC address to remove (format: AA:BB:CC:DD:EE:FF).
    """
    _require(mac, "mac")
    return await _cmd(f"dhcp_reserve del {mac}")


# ═══════════════════════════════════════════════════════════════════════════
# PORT FORWARDING
# ═══════════════════════════════════════════════════════════════════════════


@mcp.tool()
async def add_portmap(
    proto: str, external_port: int, internal_ip: str, internal_port: int
) -> str:
    """Add a port forwarding rule through the NAT router.

    Args:
        proto: Protocol - "TCP" or "UDP".
        external_port: Port number exposed on the STA (upstream) side.
        internal_ip: Internal device IP or device name (from DHCP reservation).
        internal_port: Port number on the internal device.
    """
    _require(proto, "proto")
    _require(internal_ip, "internal_ip")
    proto = proto.upper()
    if proto not in ("TCP", "UDP"):
        raise ValueError("Protocol must be TCP or UDP")
    return await _cmd(f"portmap add {proto} {external_port} {internal_ip} {internal_port}")


@mcp.tool()
async def delete_portmap(proto: str, external_port: int) -> str:
    """Delete a port forwarding rule.

    Args:
        proto: Protocol - "TCP" or "UDP".
        external_port: The external port number of the mapping to delete.
    """
    _require(proto, "proto")
    proto = proto.upper()
    if proto not in ("TCP", "UDP"):
        raise ValueError("Protocol must be TCP or UDP")
    return await _cmd(f"portmap del {proto} {external_port}")


# ═══════════════════════════════════════════════════════════════════════════
# FIREWALL (ACL)
# ═══════════════════════════════════════════════════════════════════════════

ACL_LISTS = ("to_sta", "from_sta", "to_ap", "from_ap")
ACL_PROTOS = ("IP", "TCP", "UDP", "ICMP")
ACL_ACTIONS = ("allow", "deny", "allow_monitor", "deny_monitor")


@mcp.tool()
async def acl_add(
    acl_list: str,
    proto: str,
    src: str,
    dst: str,
    action: str,
    src_port: str = "*",
    dst_port: str = "*",
) -> str:
    """Add a firewall ACL rule to a NAT router.

    Use to_ap/from_ap to filter by local client IPs.
    Use to_sta/from_sta for internet-side filtering (client IPs hidden by NAT).

    Lists:
    - to_ap: Client -> Router (Pre-NAT upstream)
    - from_ap: Router -> Client (Post-NAT downstream)
    - from_sta: Router -> Internet (Post-NAT upstream)
    - to_sta: Internet -> Router (Pre-NAT downstream)

    Parameters:
    - acl_list: 'to_ap', 'from_ap', 'to_sta', or 'from_sta'.
    - proto: 'IP', 'TCP', 'UDP', or 'ICMP'.
    - src/dst: IP, CIDR, 'any', or DHCP device name.
    - action: 'allow', 'deny', 'allow_monitor', 'deny_monitor'.
    - src_port/dst_port: Port number or '*' (TCP/UDP only).
    """
    if acl_list not in ACL_LISTS:
        raise ValueError(f"acl_list must be one of {ACL_LISTS}")
    proto = proto.upper()
    if proto not in ACL_PROTOS:
        raise ValueError(f"proto must be one of {ACL_PROTOS}")
    action = action.lower()
    if action not in ACL_ACTIONS:
        raise ValueError(f"action must be one of {ACL_ACTIONS}")
    # Ports are only accepted by the CLI for TCP/UDP; IP/ICMP don't take ports
    if proto in ("TCP", "UDP"):
        return await _cmd(f"acl {acl_list} {proto} {src} {src_port} {dst} {dst_port} {action}")
    else:
        return await _cmd(f"acl {acl_list} {proto} {src} {dst} {action}")


@mcp.tool()
async def acl_delete(acl_list: str, index: int) -> str:
    """Delete a firewall ACL rule by its index.

    Args:
        acl_list: ACL list name: to_sta, from_sta, to_ap, or from_ap.
        index: Zero-based index of the rule to delete.
    """
    if acl_list not in ACL_LISTS:
        raise ValueError(f"acl_list must be one of {ACL_LISTS}")
    return await _cmd(f"acl {acl_list} del {index}")


@mcp.tool()
async def acl_clear(acl_list: str) -> str:
    """Clear all rules from a firewall ACL list.

    Args:
        acl_list: ACL list name: to_sta, from_sta, to_ap, or from_ap.
    """
    if acl_list not in ACL_LISTS:
        raise ValueError(f"acl_list must be one of {ACL_LISTS}")
    return await _cmd(f"acl {acl_list} clear")


@mcp.tool()
async def acl_clear_stats(acl_list: str) -> str:
    """Clear hit count statistics for a firewall ACL list.

    Args:
        acl_list: ACL list name: to_sta, from_sta, to_ap, or from_ap.
    """
    if acl_list not in ACL_LISTS:
        raise ValueError(f"acl_list must be one of {ACL_LISTS}")
    return await _cmd(f"acl {acl_list} clear_stats")


# ═══════════════════════════════════════════════════════════════════════════
# PCAP PACKET CAPTURE
# ═══════════════════════════════════════════════════════════════════════════


@mcp.tool()
async def pcap_get_mode() -> str:
    """Get the current PCAP capture mode (off, acl, or promisc)."""
    return await _cmd("pcap mode")


@mcp.tool()
async def pcap_set_mode(mode: str) -> str:
    """Set the PCAP capture mode.

    Modes:
      - off: Capture disabled.
      - acl: Only capture packets matching ACL rules with monitor flag.
      - promisc: Capture all AP client traffic.

    Args:
        mode: Capture mode: "off", "acl", or "promisc".
    """
    mode = mode.lower()
    if mode not in ("off", "acl", "promisc"):
        raise ValueError("mode must be 'off', 'acl', or 'promisc'")
    return await _cmd(f"pcap mode {mode}")


@mcp.tool()
async def pcap_status() -> str:
    """Show PCAP capture statistics: client connection, captured/dropped packets."""
    return await _cmd("pcap status")


@mcp.tool()
async def pcap_get_snaplen() -> str:
    """Get the current PCAP snaplen (max bytes captured per packet)."""
    return await _cmd("pcap snaplen")


@mcp.tool()
async def pcap_set_snaplen(snaplen: int) -> str:
    """Set the PCAP snaplen (max bytes captured per packet).

    Args:
        snaplen: Bytes per packet, 64-1600. Lower = more packets in buffer, higher = full content.
    """
    if snaplen < 64 or snaplen > 1600:
        raise ValueError("snaplen must be between 64 and 1600")
    return await _cmd(f"pcap snaplen {snaplen}")

# ═══════════════════════════════════════════════════════════════════════════
# TTL OVERRIDE
# ═══════════════════════════════════════════════════════════════════════════


@mcp.tool()
async def get_ttl() -> str:
    """Get the current TTL override setting for upstream STA packets."""
    return await _cmd("set_ttl")


@mcp.tool()
async def set_ttl(ttl: int) -> str:
    """Set the TTL override for all upstream (STA) packets. Takes effect immediately.

    Args:
        ttl: TTL value 1-255, or 0 to disable override (use original TTL).
    """
    if ttl < 0 or ttl > 255:
        raise ValueError("TTL must be 0-255")
    return await _cmd(f"set_ttl {ttl}")

# ═══════════════════════════════════════════════════════════════════════════
# SYSTEM COMMANDS
# ═══════════════════════════════════════════════════════════════════════════


@mcp.tool()
async def restart() -> str:
    """Restart the ESP32. The telnet connection will be lost.
    You will need to reconnect after the device reboots (~5 seconds)."""
    try:
        result = await _cmd("restart")
    except Exception:
        result = "Restart command sent. Device is rebooting..."
    # Force disconnect since the device is rebooting
    await _get_conn().disconnect()
    return result


@mcp.tool()
async def factory_reset() -> str:
    """Erase ALL settings (WiFi, port mappings, DHCP reservations, ACLs, passwords)
    and restart with factory defaults. This is irreversible!"""
    try:
        result = await _cmd("factory_reset")
    except Exception:
        result = "Factory reset command sent. Device is rebooting with defaults..."
    await _get_conn().disconnect()
    return result


# ═══════════════════════════════════════════════════════════════════════════
# NETWORK TRACE (PCAP CAPTURE + TCPDUMP)
# ═══════════════════════════════════════════════════════════════════════════


# PCAP global header: magic, version 2.4, timezone 0, sigfigs 0,
# snaplen 65535, link type DLT_EN10MB (1)
_PCAP_GLOBAL_HEADER = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


async def _pcap_receive(
    host: str, port: int, duration: float, max_bytes: int,
) -> bytes:
    """Connect to the ESP32 PCAP TCP stream and collect raw data.

    The ESP32 streams a full pcap file (global header + packet records)
    over TCP on port 19000. We read until *duration* seconds elapse or
    *max_bytes* are received.
    """
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port), timeout=CONNECT_TIMEOUT,
    )
    buf = bytearray()
    try:
        end_time = asyncio.get_event_loop().time() + duration
        while asyncio.get_event_loop().time() < end_time:
            remaining = end_time - asyncio.get_event_loop().time()
            if remaining <= 0:
                break
            try:
                chunk = await asyncio.wait_for(
                    reader.read(16384), timeout=min(remaining, 1.0),
                )
            except asyncio.TimeoutError:
                continue
            if not chunk:
                break
            buf.extend(chunk)
            if len(buf) >= max_bytes:
                break
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    return bytes(buf)


@mcp.tool()
async def network_trace(
    duration: int = 10,
    mode: str = "",
    tcpdump_filter: str = "",
    save_pcap_path: str = "",
    verbose: bool = False,
    max_packets: int = 0,
) -> str:
    """Capture live network traffic from the ESP32 and analyse it with tcpdump.

    Connects to the ESP32 PCAP stream (TCP 19000), collects packets for the
    requested duration, then runs local tcpdump to produce human-readable output.

    Prerequisites: PCAP capture must be enabled on the router (mode "acl" or
    "promisc").  If *mode* is given, the tool sets it automatically before
    capturing.  tcpdump must be installed on this machine.

    Args:
        duration: Capture time in seconds (1-120, default 10).
        mode: Optionally set PCAP mode before capture: "acl" or "promisc".
              Leave empty to use the current mode.
        tcpdump_filter: Optional BPF filter for tcpdump (e.g. "tcp port 80",
                        "host 192.168.4.2", "udp and port 53").
        save_pcap_path: If set, save the raw pcap file to this path (for
                        opening in Wireshark later).
        verbose: If True, use tcpdump -v for more detail.
        max_packets: Maximum number of packets to show (0 = all captured).
    """
    # Validate
    if duration < 1 or duration > 120:
        raise ValueError("duration must be 1-120 seconds")
    if not shutil.which("tcpdump"):
        raise RuntimeError(
            "tcpdump is not installed. Install it with: sudo apt install tcpdump"
        )

    # Optionally set capture mode
    mode_msg = ""
    if mode:
        mode = mode.lower()
        if mode not in ("acl", "promisc"):
            raise ValueError("mode must be 'acl' or 'promisc'")
        mode_msg = await _cmd(f"pcap mode {mode}")

    # Capture raw pcap data from the ESP32 stream
    max_bytes = 4 * 1024 * 1024  # 4 MB safety cap
    try:
        pcap_data = await _pcap_receive(ESP_HOST, PCAP_PORT, duration, max_bytes)
    except (OSError, asyncio.TimeoutError) as e:
        return (
            f"Failed to connect to PCAP stream at {ESP_HOST}:{PCAP_PORT}: {e}\n"
            "Make sure PCAP capture is enabled (pcap mode acl/promisc) and "
            "no other client (e.g. Wireshark) is already connected."
        )

    if len(pcap_data) == 0:
        return (
            "No data received from PCAP stream. Possible causes:\n"
            "- PCAP mode is 'off' (use mode='promisc' or mode='acl')\n"
            "- No traffic during the capture window\n"
            "- Another client is already connected to the PCAP stream"
        )

    # Validate we got a pcap header (magic number)
    if len(pcap_data) >= 4:
        magic = struct.unpack_from("<I", pcap_data, 0)[0]
        if magic not in (0xA1B2C3D4, 0xD4C3B2A1):
            return (
                f"Received {len(pcap_data)} bytes but data does not start with "
                "a valid PCAP header. The stream may not be active."
            )

    # Write to temp file
    tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
    try:
        tmp.write(pcap_data)
        tmp.close()

        # Optionally save a copy
        if save_pcap_path:
            shutil.copy2(tmp.name, save_pcap_path)

        # Build tcpdump command
        cmd_parts = ["tcpdump", "-r", tmp.name, "-n", "--no-promiscuous-mode"]
        if verbose:
            cmd_parts.append("-v")
        if max_packets > 0:
            cmd_parts.extend(["-c", str(max_packets)])
        if tcpdump_filter:
            cmd_parts.extend(tcpdump_filter.split())

        proc = await asyncio.create_subprocess_exec(
            *cmd_parts,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
        output = stdout.decode(errors="replace")
        errors = stderr.decode(errors="replace")

        # tcpdump prints the summary line to stderr
        # (e.g. "X packets captured, Y packets received by filter")
        summary_lines = [
            l for l in errors.splitlines()
            if "packet" in l or "reading from" in l.lower()
        ]
        non_summary = [
            l for l in errors.splitlines()
            if l not in summary_lines and l.strip()
        ]

        result_parts = []
        if mode_msg:
            result_parts.append(f"[PCAP mode set] {mode_msg}")
        result_parts.append(
            f"[Capture] {len(pcap_data)} bytes from {ESP_HOST}:{PCAP_PORT} "
            f"over {duration}s"
        )
        if save_pcap_path:
            result_parts.append(f"[Saved] {save_pcap_path}")
        if summary_lines:
            result_parts.append("\n".join(summary_lines))
        if non_summary:
            result_parts.append("[tcpdump stderr] " + "\n".join(non_summary))
        if output.strip():
            result_parts.append(output.strip())
        elif not non_summary:
            result_parts.append(
                "(no packets matched the filter)" if tcpdump_filter
                else "(no packets in capture)"
            )

        return "\n\n".join(result_parts)

    finally:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass


# ═══════════════════════════════════════════════════════════════════════════
# RAW COMMAND (ESCAPE HATCH)
# ═══════════════════════════════════════════════════════════════════════════


@mcp.tool()
async def raw_command(command: str) -> str:
    """Send a raw command to the ESP32 console and return the response.
    Use this for commands not covered by other tools, or for debugging.

    Args:
        command: The exact command string to send to the ESP32 console.
    """
    _require(command, "command")
    return await _cmd(command)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="ESP32 NAT Router MCP Bridge")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "streamable-http"],
        default="stdio",
        help="MCP transport (default: stdio)",
    )
    parser.add_argument(
        "--host", default="0.0.0.0", help="Bind address for HTTP transports (default: 0.0.0.0)"
    )
    parser.add_argument(
        "--port", type=int, default=8000, help="Port for HTTP transports (default: 8000)"
    )
    args = parser.parse_args()

    if args.transport == "stdio":
        mcp.run(transport="stdio")
    else:
        mcp.run(transport=args.transport, host=args.host, port=args.port)
