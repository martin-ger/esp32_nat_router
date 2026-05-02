# ESP32 WiFi L2 Repeater

This firmware turns the ESP32 into a **transparent Layer 2 WiFi bridge**: it connects to an existing upstream WiFi network as a STA client and re-broadcasts it as a new AP, with no NAT and no subnet boundary between the two sides. Clients on the AP side join the upstream network directly — they receive IP addresses from the upstream DHCP server, live on the upstream subnet, and are fully visible to other devices there.

For the full NAT-router variant (VPN, port forwarding, DHCP reservations, separate subnet) see the [esp32_nat_router master branch](https://github.com/martin-ger/esp32_nat_router).

## How It Differs from the NAT Router

| | NAT Router | L2 Repeater (this firmware) |
|--|--|--|
| AP clients' IP range | Separate private subnet | Same subnet as upstream network |
| IP assignment | ESP32's own DHCP server | Upstream DHCP server (proxied) |
| Upstream sees client MACs | No — only STA MAC | No — only STA MAC (802.11 constraint) |
| mDNS / Bonjour / UPnP | Blocked at subnet boundary | Works transparently |
| Port forwarding | Yes | Not needed / not available |
| WireGuard VPN | Yes | Not available |
| DHCP reservations | Yes (ESP32-managed) | Not applicable (upstream manages IPs) |

## Use Cases

- Transparent WiFi range extender where clients need to stay on the same subnet
- IoT bridging where devices use mDNS, Bonjour, or UPnP for discovery
- Extending a network without reconfiguring any upstream devices
- Debugging: the ESP32 sits invisibly between devices with no routing artefacts
- Converting a corporate (WPA2-Enterprise) network to WPA2-PSK for simple devices, on the same subnet

## Key Features

- **L2 Bridging**: Software MAC-translation bridge at the lwIP netif layer — AP clients live on the upstream subnet
- **Transparent DHCP**: Upstream DHCP server serves clients directly via DHCP snooping and XID proxying
- **Proxy ARP**: ESP32's own management IP is answered locally so clients can reach the web UI
- **mDNS / Bonjour**: Device is reachable as `<hostname>.local` from both STA and AP sides; AP-side mDNS queries are answered by a built-in responder and also forwarded upstream
- **WPA2-Enterprise Support**: Connect to corporate networks (PEAP, TTLS, TLS) and re-broadcast as WPA2-PSK
- **5 GHz WiFi**: Dual-band on ESP32-C5 with configurable band preference
- **Channel Lock**: AP channel auto-follows the upstream AP channel (single-radio constraint)
- **Web Interface**: Same web UI as the NAT router for configuration and status
- **Serial Console**: Full CLI with repeater-specific diagnostics (`repeater show|fdb|xid|clear`)
- **Remote Console**: Network-accessible CLI via TCP (password protected)
- **Firewall (ACL)**: Stateless packet filtering on all four traffic directions
- **Packet Capture**: Live PCAP stream to Wireshark via TCP
- **LED Status Indicator**: Plain GPIO or addressable RGB (WS2812/SK6812) with color-coded status
- **OLED Display**: 72x40 SSD1306 I2C display (ESP32-C3 and ESP32-S3)
- **MQTT Home Assistant**: Telemetry and connected-client presence via MQTT with HA auto-discovery
- **OTA Updates**: Flash new firmware directly from the Web UI

The maximum number of simultaneously connected WiFi clients is 8 (5 on ESP32-C3) due to RAM constraints.

---

## First Boot

After first boot, the repeater offers an open WiFi network with the SSID **ESP32_WiFi_Repeater**. During this unconfigured phase, the AP runs a DHCP server so you can reach the setup page.

1. Connect to **ESP32_WiFi_Repeater**
2. Open **http://esp32-wifi-repeater.local** (or http://192.168.4.1) in your browser
3. On the Getting Started page, enter your upstream WiFi SSID and password, and set a name and password for the new AP
4. Click **Save & Reboot**

After reboot the AP DHCP server is disabled and the upstream DHCP server takes over. AP clients will receive IPs from upstream within a few seconds of connecting. You can then still reach the ESP via "esp32-wifi-repeater.local".

---

## Flashing Pre-built Binaries

### esptool (Command Line)

Install [esptool](https://github.com/espressif/esptool):

```bash
python3 -m pip install esptool
```

Flash using the pre-built binaries from the `firmware_*` directories. All four files are required for a fresh install.

#### ESP32

```bash
esptool.py --chip esp32 \
--before default_reset --after hard_reset write_flash \
-z --flash_mode dio --flash_freq 40m --flash_size detect \
0x1000  firmware_esp32/bootloader.bin \
0x8000  firmware_esp32/partition-table.bin \
0xf000  firmware_esp32/ota_data_initial.bin \
0x20000 firmware_esp32/esp32_nat_router.bin
```

#### ESP32-C3

```bash
esptool.py --chip esp32c3 \
--before default_reset --after hard_reset write_flash \
-z --flash_size detect \
0x0     firmware_esp32c3/bootloader.bin \
0x8000  firmware_esp32c3/partition-table.bin \
0xf000  firmware_esp32c3/ota_data_initial.bin \
0x20000 firmware_esp32c3/esp32_nat_router.bin
```

#### ESP32-C5

```bash
esptool.py --chip esp32c5 \
--before default_reset --after hard_reset write_flash \
-z --flash_size detect \
0x2000  firmware_esp32c5/bootloader.bin \
0x8000  firmware_esp32c5/partition-table.bin \
0xf000  firmware_esp32c5/ota_data_initial.bin \
0x20000 firmware_esp32c5/esp32_nat_router.bin
```

#### ESP32-C6

```bash
esptool.py --chip esp32c6 \
--before default_reset --after hard_reset write_flash \
-z --flash_size detect \
0x0     firmware_esp32c6/bootloader.bin \
0x8000  firmware_esp32c6/partition-table.bin \
0xf000  firmware_esp32c6/ota_data_initial.bin \
0x20000 firmware_esp32c6/esp32_nat_router.bin
```

#### ESP32-S3

If the JTAG-USB causes problems during flash, add `--no-stub`.

```bash
esptool.py --chip esp32s3 \
--before default_reset --after hard_reset write_flash \
-z --flash_size detect \
0x0     firmware_esp32s3/bootloader.bin \
0x8000  firmware_esp32s3/partition-table.bin \
0xf000  firmware_esp32s3/ota_data_initial.bin \
0x20000 firmware_esp32s3/esp32_nat_router.bin
```

### OTA Updates

After initial flashing, you can update firmware from the web UI. Download the latest `esp32_nat_router.bin` for your chip, go to the `/config` page, scroll to the OTA section, select the file, and click **Update Firmware**. All settings are preserved. If the new firmware fails to boot, the device rolls back to the previous version.

### Clearing Configuration

Re-flashing preserves settings in NVS. To wipe all settings:

- **CLI**: `factory_reset`
- **BOOT button**: Hold for 5 seconds (LED blinks rapidly during the hold)
- **Full erase**: `esptool.py --chip <chip> erase_flash` (also erases firmware)

---

## Building from Source

The repeater mode is enabled via a Kconfig option. Download and set up ESP-IDF (V5.5.x), then:

```bash
idf.py set-target <esp32|esp32c3|esp32c5|esp32c6|esp32s3>
idf.py menuconfig   # Enable: WiFi Repeater → Enable L2 WiFi AP-STA repeater mode
idf.py build
idf.py flash monitor
```

To build all supported targets:

```bash
./build_all_targets.sh
```

### USB Serial/JTAG Console

Newer ESP32 boards (C3, C6, S3) have a built-in USB Serial/JTAG controller. If the USB port connects directly to it, the UART console is not available. Switch via menuconfig:

`Component config → ESP System Settings → Channel for console output → USB Serial/JTAG Controller`

---

## Web Interface

Connect to the AP (or after setup, to the upstream network at the ESP32's STA IP) and open the web UI.

### System Status (`/`)

- AP SSID and number of connected clients
- Uplink SSID and signal strength
- STA IP address (the ESP32's IP on the upstream network)
- Bytes sent/received, uptime
- Capture mode and status

### Getting Started (`/setup`)

Simplified first-time setup: set AP name/password and upstream WiFi credentials.

### WiFi Scan (`/scan`)

Scan upstream networks and click **Connect** to pre-fill the setup page with the selected SSID. ESP32-C5 shows a band column (2.4G / 5G).

### Configuration (`/config`)

All advanced settings:

- **Access Point**: SSID, password, IP address (management only), MAC, security mode (WPA2/WPA3), hidden SSID, enable/disable AP
- **Station (Uplink)**: SSID, password, WPA2-Enterprise settings, MAC address, static IP, band preference (ESP32-C5)
- **Remote Console**: enable/disable, port, interface binding, idle timeout
- **Packet Capture**: mode, snaplen, status
- **OTA Firmware Update**: upload `.bin` file to update firmware
- **Device Management**: config backup/restore, reboot, disable web UI

#### Config Backup / Restore

**Export (Write Config):** Optionally enter a passphrase, then click **Write Config**. Without a passphrase the file is plain JSON with WiFi passwords omitted. With a passphrase the file is fully encrypted (XChaCha20-Poly1305, PBKDF2-derived key) and includes all secrets. Store encrypted backups safely — the passphrase is never saved on the device.

**Import (Read Config):** Enter the passphrase if the file was encrypted, select the file, click **Read Config**. The device reboots automatically after a successful import.

### Firewall (`/firewall`)

Configure ACL packet-filtering rules — see [Firewall](#firewall-acl) below.

### Password Protection

Protect `/config` and other pages with a password:

```
set_router_password mypassword
```

To disable: `set_router_password ""`

Sessions expire after 30 minutes of inactivity.

### Disabling the Web Interface

```
web_ui disable    # disable (survives reboot)
web_ui enable     # re-enable
```

---

## CLI Reference

Connect via serial (115200 bps) or the [Remote Console](#remote-console). Use `help [<command>]` for built-in documentation.

Special characters (including spaces) can be encoded as `%20` etc. (HTTP-style hex encoding).

### System & Diagnostics

```
help [<command>]           Show help for all or one command
version                    Show chip and SDK version
restart                    Software reset
factory_reset              Erase all NVS settings and restart
heap                       Show free and minimum heap
tasks                      Show running tasks
ping <host> [-c n] [-s bytes]   ICMP echo
show [status|config|acl|ota]    Show router state, config, ACL rules, or OTA info
bytes [reset]              Show or reset STA byte counts
client_stats [enable|disable]   Per-client TX/RX stats (disabled by default)
```

### Repeater Diagnostics

These commands are specific to the L2 bridge mode:

```
repeater [show|fdb|xid|clear]
  show   Print FDB and DHCP XID map (default)
  fdb    Print the Forwarding Database (IP → MAC → TTL)
  xid    Print the DHCP transaction-ID map (XID → client MAC → TTL)
  clear  Flush all FDB entries
```

The **FDB** (Forwarding Database) maps upstream IP addresses to the real MAC addresses of AP-side clients. It is populated automatically as clients send traffic and via DHCP ACK snooping. TTL is 600 seconds, refreshed on each seen packet.

The **XID map** is a transient table used to route DHCP replies back to the correct client before the FDB has an entry. Entries expire after 30 seconds.

### WiFi — STA (Upstream)

```
scan                              Scan for upstream WiFi networks
set_sta <ssid> <pass> [-u user] [-a identity] [-e 0-3] [-p 0-3] [-c 0|1] [-t 0|1]
                                  Set upstream SSID, password, and optional WPA2-Enterprise params
set_sta_static <ip> <mask> <gw>   Set static IP for the STA interface
set_sta_static dhcp               Revert to DHCP
set_sta_mac <o1> <o2> <o3> <o4> <o5> <o6>   Set STA MAC address
set_sta_band [auto|2.4|5]         Band preference (ESP32-C5 only)
```

#### WPA2-Enterprise flags

| Flag | Description |
|------|-------------|
| `-u` | Enterprise username |
| `-a` | Enterprise identity (defaults to username) |
| `-e` | EAP method: 0=Auto, 1=PEAP, 2=TTLS, 3=TLS |
| `-p` | TTLS Phase 2: 0=MSCHAPv2, 1=MSCHAP, 2=PAP, 3=CHAP |
| `-c 1` | Use CA certificate bundle for server validation |
| `-t 1` | Skip certificate time check (if device has no RTC) |

### WiFi — AP (Hotspot)

```
set_ap <ssid> <pass>              Set AP SSID and password
set_ap_ip <ip>                    Set the ESP32's management IP (AP interface only)
set_ap_hidden [on|off]            Hide/show AP SSID
set_ap_auth [wpa2|wpa3|wpa2wpa3]  Set AP authentication mode
set_ap_mac <o1> <o2> <o3> <o4> <o5> <o6>   Set AP MAC address
ap [enable|disable]               Enable/disable AP interface immediately
```

> **Note:** The AP IP (`set_ap_ip`) is the ESP32's management address, reachable for the web UI and console. It is **not** the gateway for AP clients — those receive the upstream gateway from the upstream DHCP server.

### Network Settings

```
set_hostname <name>               DHCP hostname for the upstream network (Option 12); also sets the mDNS name (<name>.local)
set_ttl [<n>|0]                   TTL override for STA-bound packets (0 = disabled)
set_tx_power <dBm>                WiFi TX power (2-20, 0 = max/default)
set_tz <TZ string>                POSIX timezone string (e.g. CET-1CEST,M3.5.0/2,M10.5.0/3)
```

### Firewall (ACL)

```
acl                                        Show all ACL rules and hit counters
acl <uplink|downlink> show                 Show one list
acl <uplink|downlink> <proto> <src> <sport> <dst> <dport> <action>   Add rule
acl <uplink|downlink> del <index>          Delete rule by index
acl <uplink|downlink> clear                Clear all rules in list
acl <uplink|downlink> clear_stats          Reset hit counters
```

Protocols: `IP`, `TCP`, `UDP`, `ICMP`. Address: `any`, CIDR (`192.168.0.0/24`), single host, or device name from a DHCP reservation. Port: `*` = any. Actions: `allow`, `deny`, `allow_monitor`, `deny_monitor`.

See [Firewall](#firewall-acl) below for details.

### Packet Capture

```
pcap mode [off|acl|promisc]       Set capture mode
pcap status                       Show capture statistics
pcap snaplen [<64-1600>]          Set max bytes per captured packet
```

### Web Interface

```
web_ui [enable|disable|port <n>]  Manage web interface
set_router_password <pass>        Set password for web UI and remote console
```

### Remote Console

```
remote_console status             Show status
remote_console enable             Enable remote console (TCP, default port 2323)
remote_console disable            Disable
remote_console port <n>           Set TCP port
remote_console bind <ap,sta>      Restrict to interface(s)
remote_console timeout <s>        Idle timeout (0 = none)
remote_console kick               Disconnect current session
```

### Logging

```
log_level [<level>] [-t <tag>]    Get/set log level (none/error/warn/info/debug/verbose)
syslog enable <server> [<port>]   Forward logs to remote syslog (UDP, default port 514)
syslog disable
```

### Hardware & LED

```
set_led_gpio [<n>|none]           GPIO for plain status LED
set_led_lowactive                 Invert LED polarity (active-low LEDs)
set_led_strip [<n>|none]          GPIO for WS2812/SK6812 addressable LED
set_oled [enable|disable]         OLED display (ESP32-C3/S3 only)
set_oled_gpio <sda> <scl>         I2C pins for OLED
set_rf_switch_XIAO [0|1]          XIAO ESP32-C6: built-in (0) or external (1) antenna
```

### MQTT

```
mqtt enable                       Start MQTT publishing
mqtt disable
mqtt broker <uri>                 Set broker URI (e.g. mqtt://192.168.1.100:1883)
mqtt user <user> <pass>           Set broker credentials
mqtt interval <s>                 Publish interval (5-3600)
mqtt rediscover                   Re-publish HA discovery configs
mqtt status
```

---

## Firewall (ACL)

The bridge includes a stateless packet-filtering firewall with two ACLs, one per forwarding direction. Both hooks sit at the `linkoutput` layer where all bridged transit traffic passes:

```
                        ESP32 L2 Bridge
                  ┌───────────────────────┐
                  │                       │
   Upstream ◄────►│  STA            AP    │◄────────► AP Clients
                  │                       │
                  └───────────────────────┘
          uplink ──►                   ◄── downlink
     (clients→internet)          (internet→clients)
```

| ACL | Direction | Typical use |
|-----|-----------|-------------|
| `uplink` | AP clients → upstream (internet) | Restrict what clients can send upstream |
| `downlink` | Upstream → AP clients (internet → clients) | Filter inbound traffic reaching AP clients |

Rules are evaluated in order; the first match wins. Unmatched packets are **allowed** (permissive default). Non-IPv4 traffic (ARP) passes through without filtering.

Each rule uses one of four actions: `allow`, `deny`, `allow_monitor` (allow + PCAP), `deny_monitor` (drop + PCAP).

**Examples:**

```bash
# Allow only DNS and HTTP/HTTPS from clients, block everything else upstream
acl uplink UDP any * any 53 allow
acl uplink TCP any * any 80 allow
acl uplink TCP any * any 443 allow
acl uplink IP any * any * deny

# Capture all DNS traffic going upstream (without blocking)
acl uplink UDP any * any 53 allow_monitor

# Block inbound access to management port from upstream
acl downlink TCP any * 192.168.x.y 80 deny

# Block a specific upstream host from reaching clients
acl downlink IP 203.0.113.50 * any * deny
```

---

## Remote Console

The bridge provides network CLI access via TCP (disabled by default):

```bash
# On the ESP32:
set_router_password mypassword
remote_console enable

# From any machine on the network:
nc 192.168.x.y 2323
```

The remote console uses plaintext TCP — only use on trusted networks or bind it to the AP interface:

```
remote_console bind ap
```

---

## Hardware

### LED Status Indicator

| State | Plain LED | Addressable LED |
|-------|-----------|-----------------|
| Not connected to upstream | Off | Red pulse (2 s breathing cycle) |
| Connecting | — | Yellow pulse |
| Connected, no traffic | On steady | Green (brightness = client count) |
| Traffic flowing | Flickering | Cyan flash |
| Factory reset in progress | — | Red/blue alternation |

Configure the LED:

```
set_led_gpio 2          # Plain LED on GPIO 2
set_led_gpio none       # Disable
set_led_strip 27        # WS2812/SK6812 on GPIO 27
set_led_strip none      # Disable
```

Common plain-LED GPIO pins by board:

| Board | GPIO |
|-------|------|
| ESP32 DevKit v1 / WROOM | 2 |
| ESP32-S3 DevKitC | 48 (RGB) |
| ESP32-C3 DevKitM / SuperMini | 8 |
| ESP32-C6 DevKitC | 8 |
| NodeMCU-32S | 2 |

### OLED Display (ESP32-C3 and ESP32-S3)

72×40 px SSD1306 over I2C. Shows SSID, uplink status and RSSI, STA IP, connected client count, and traffic counters.

```
set_oled enable              # Enable (requires reboot)
set_oled gpio <sda> <scl>    # Set I2C pins (default: SDA=5, SCL=6)
```

### Factory Reset via BOOT Button

Hold the BOOT button for **5 seconds**. The LED blinks rapidly during the hold. All NVS settings are erased; the device reboots to factory defaults (open AP "ESP32_NAT_Router").

| Chip | BOOT button GPIO |
|------|-----------------|
| ESP32, ESP32-S2, ESP32-S3 | GPIO 0 |
| ESP32-C3, ESP32-C2, ESP32-C6 | GPIO 9 |
| ESP32-C5 | GPIO 28 |

---

## 5 GHz Band Selection (ESP32-C5)

The ESP32-C5 supports dual-band WiFi. Since it has a single radio, the AP channel always follows the STA channel.

```
set_sta_band auto    # Strongest signal (default)
set_sta_band 2.4     # Prefer 2.4 GHz
set_sta_band 5       # Prefer 5 GHz
```

The router scans for the configured SSID, filters by the preferred band, and falls back automatically if no AP is found on that band.

---

## MQTT Home Assistant Integration

Publishes telemetry to an MQTT broker with HA auto-discovery. Enable via `idf.py menuconfig` → **MQTT Home Assistant** (enabled by default).

```
mqtt broker mqtt://192.168.1.100:1883
mqtt user myuser mypassword   # if required
mqtt enable
```

The bridge appears automatically in HA under **Settings → Devices & Services → MQTT**.

### Entities

| Entity | Type | Description |
|--------|------|-------------|
| Uplink Status | Binary Sensor | Connected to upstream AP |
| Connected Clients | Sensor | Number of AP clients |
| Bytes Sent / Received | Sensor | Cumulative traffic through the bridge |
| Uplink RSSI | Sensor | Upstream signal strength (dBm) |
| Uplink SSID | Sensor | Upstream network name |
| Free Heap | Sensor | Available RAM |
| Uptime | Sensor | Seconds since boot |
| Restart | Button | Remotely restart the bridge |
| Web UI | Switch | Enable/disable web interface |
| Remote Console | Switch | Enable/disable remote console |
| AP Interface | Switch | Enable/disable WiFi hotspot |

---

## Packet Capture

Streams live traffic to Wireshark via TCP on port 19000.

| Mode | Description |
|------|-------------|
| `off` | Disabled (default) |
| `acl` | Capture only packets matching ACL rules with `allow_monitor` / `deny_monitor` |
| `promisc` | Capture all AP-side traffic |

```bash
# Pipe to Wireshark:
nc <ESP32-IP> 19000 | wireshark -k -i -
```

```
pcap mode promisc      # Start full AP capture
pcap mode acl          # Selective capture (ACL monitor rules only)
pcap mode off          # Stop
pcap snaplen 1500      # Full frames; use 128 for headers only
pcap status            # Show packet/drop counts
```

---

## MCP Bridge (Beta)

Allows AI assistants (e.g. Claude) to configure and monitor the bridge programmatically via the Model Context Protocol.

**Prerequisites:** Remote console must be enabled with a password set.

```bash
pip install fastmcp telnetlib3
export ESP_NAT_HOST=192.168.x.y
export ESP_NAT_PASSWORD=mypassword
python esp_nat_bridge.py
```

**Claude Code integration** — add to `~/.claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "esp32-repeater": {
      "command": "python",
      "args": ["esp_nat_bridge.py"],
      "env": {
        "ESP_NAT_HOST": "192.168.x.y",
        "ESP_NAT_PASSWORD": "mypassword"
      }
    }
  }
}
```

---

## Security

### Attack Surface

| Interface | Protocol | Default Port | Auth | Encryption | Default |
|-----------|----------|-------------|------|------------|---------|
| Web UI | HTTP | 80 | Optional password | None (plaintext) | Enabled |
| Remote Console | TCP | 2323 | Optional password | None (plaintext) | Disabled |
| MCP Bridge | TCP | 3000 | None | None (plaintext) | Disabled |
| PCAP stream | TCP | 19000 | None | None (plaintext) | Off |

### Hardening Checklist

| Step | Command |
|------|---------|
| Set a strong password | `set_router_password <password>` |
| Restrict web UI to AP interface | `web_ui bind ap` |
| Restrict remote console to AP interface | `remote_console bind ap` |
| Disable remote console if not needed | `remote_console disable` |
| Disable web UI after initial config | `web_ui disable` |
| Block management from upstream (ACL) | `acl add to_esp TCP any * any 80 deny` |
| Disable PCAP when not in use | `pcap mode off` |
| Erase NVS before decommissioning | `esptool.py erase_flash` |

### Credential Storage

Passwords are stored as salted SHA-256 hashes in NVS. WiFi credentials are stored as plaintext strings. Physical serial or flash access grants access to these. NVS is **not** erased by re-flashing; wipe explicitly with `esptool.py erase_flash` or `factory_reset`.

---

## How the Bridge Works

The ESP32 has a single radio that cannot transmit and receive simultaneously. It cannot run a true WDS (4-address 802.11) bridge. Instead, it performs **software MAC translation at the lwIP netif layer**:

- Every frame going upstream has its Ethernet source MAC replaced with the ESP32's STA MAC (required by the 802.11 driver).
- Every frame coming downstream has its Ethernet destination MAC replaced with the correct AP client MAC, looked up in the **Forwarding Database (FDB)** by destination IP.
- DHCP is snooped in both directions to populate the FDB before any unicast traffic arrives and to proxy DHCP exchanges through the bridge.
- ARP is rewritten on both sides to maintain consistent MAC-to-IP mappings across the bridge.

The upstream network's ARP table maps every client IP to the ESP32's STA MAC — this is the fundamental constraint of 802.11 infrastructure mode and cannot be avoided without WDS support on the upstream AP.

For a detailed description of the bridging architecture, MAC translation logic, DHCP snooping, and known limitations, see [Layer2Bridging.md](Layer2Bridging.md).

### Limitations

- **IPv6 is not bridged.** IPv6 frames are processed by the ESP32's own stack only.
- **Non-IP/ARP frames are not forwarded.** Only EtherType `0x0800` (IPv4) and `0x0806` (ARP) are bridged; 802.1Q, IPv6, and others are passed to the local stack only.
- **Upstream ARP table shows only the STA MAC** for all clients — tools that use MAC for client identity (e.g., some DHCP servers, RADIUS) will see one MAC for all bridge clients.
- **True MAC transparency** (WDS / 4-address mode) is not supported without upstream AP cooperation.
- **mDNS is handled but not fully transparent.** The bridge answers A-record queries for `<hostname>.local` from AP clients directly. Other mDNS service queries (e.g. `_http._tcp.local`) are forwarded upstream so upstream responders can reply; upstream mDNS traffic is mirrored to AP-side clients. Full peer-to-peer mDNS between an AP client and an upstream device works as long as both sides generate traffic first.

---

## Performance

Throughput depends on WiFi signal quality and radio congestion. With a single shared half-duplex radio serving both AP and STA, expect 3–10 Mbps under typical conditions. Disabling unused features (packet capture, MQTT) helps on RAM-constrained chips like the ESP32-C3.
