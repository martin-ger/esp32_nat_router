# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ESP32 NAT Router - WiFi-based NAT router firmware for ESP32 microcontrollers. Enables WiFi range extension, guest networks, WPA2-Enterprise conversion, and port mapping.

## Build Commands

### ESP-IDF (Primary)
```bash
idf.py menuconfig      # Configure build options
idf.py build           # Build the project
idf.py flash           # Flash to device
idf.py monitor         # Watch serial output (115200 bps)
idf.py flash monitor   # Flash and monitor combined
```

### PlatformIO (Alternative)
```bash
pio run                # Build
pio run -t upload      # Flash
pio device monitor     # Serial monitor
```

## Architecture

### Source Structure
```
main/
├── esp32_nat_router.c   # Entry point: WiFi init, event handling, LED status, port mapping, DHCP reservations
├── http_server.c        # Web UI server at 192.168.4.1 (pages: /, /config, /mappings)
├── pages.h              # HTML/CSS for web interface
└── cmd_decl.h           # Command declarations

components/
├── acl/                 # Stateless packet filtering firewall (4 ACL lists, 16 rules each)
├── dhcpserver/          # Custom DHCP server with reservation support (overrides ESP-IDF built-in)
├── cmd_router/          # CLI commands: set_sta, set_ap, portmap, dhcp_reserve, disable/enable, set_web_password, show, acl
├── cmd_system/          # System commands: free, heap, restart, factory_reset, tasks
└── cmd_nvs/             # NVS storage commands: nvs_set, nvs_get, nvs_erase
```

### Custom DHCP Server Component
The `components/dhcpserver/` directory contains a custom DHCP server implementation that overrides the ESP-IDF built-in version using linker wrapping (`--wrap`).

**Structure:**
```
components/dhcpserver/
├── CMakeLists.txt                 # Build config with --wrap linker flags
├── dhcpserver.c                   # Implementation (functions use __wrap_ prefix)
└── include/dhcpserver/
    ├── dhcpserver.h               # Public API
    └── dhcpserver_options.h       # DHCP option definitions
```

**How it works:**
- `CONFIG_LWIP_DHCPS` remains enabled (ESP-IDF config options work normally)
- Linker `--wrap=<func>` redirects all calls to `__wrap_<func>` implementations
- Original ESP-IDF functions available via `__real_<func>()` if needed

**Wrapped functions:**
- `dhcps_new`, `dhcps_delete`, `dhcps_start`, `dhcps_stop`
- `dhcps_option_info`, `dhcps_set_option_info`
- `dhcp_search_ip_on_mac`, `dhcps_set_new_lease_cb`
- `dhcps_dns_setserver`, `dhcps_dns_getserver` (and `_by_type` variants)

**To modify DHCP behavior:** Edit `components/dhcpserver/dhcpserver.c`

### Key Global Variables (in router_globals.h)
- `ssid`, `passwd` - Upstream WiFi credentials
- `ap_ssid`, `ap_passwd` - Access point credentials
- `static_ip`, `subnet_mask`, `gateway_addr` - Static IP config
- `my_ip`, `my_ap_ip` - Current IP addresses
- `portmap_tab[]` - Port mapping table (max `IP_PORTMAP_MAX` entries)
- `dhcp_reservations[]` - DHCP reservation table (max 16 entries)
- `ap_connect` - AP connection status flag
- `connect_count` - Number of connected clients

### DHCP Reservations
The custom DHCP server supports IP reservations - assigning fixed IPs to specific MAC addresses.

**Data structure** (`router_globals.h`):
```c
struct dhcp_reservation_entry {
    uint8_t mac[6];                              // Client MAC address
    uint32_t ip;                                 // Reserved IP address
    char name[DHCP_RESERVATION_NAME_LEN];        // Optional device name (32 chars)
    uint8_t valid;                               // Entry active flag
};
```

**Functions** (`esp32_nat_router.c`):
- `add_dhcp_reservation(mac, ip, name)` - Add/update reservation
- `del_dhcp_reservation(mac)` - Remove reservation by MAC
- `lookup_dhcp_reservation(mac)` - Get reserved IP for MAC (returns 0 if none)
- `print_dhcp_reservations()` - Print all reservations to console

**Storage:** Persisted in NVS as blob under key `"dhcp_res"`

### ACL Firewall Component
The `components/acl/` directory implements a stateless packet filtering firewall with four ACL lists.

**Structure:**
```
components/acl/
├── CMakeLists.txt
├── acl.c                    # Implementation: packet matching, rule management
└── include/acl.h            # Public API and data structures
```

**Network topology and ACL naming:**
```
                          ESP32 NAT Router
                    ┌───────────────────────┐
                    │                       │
Internet ──to_sta──►│  STA            AP    │◄──to_ap─── Clients
         ◄─from_sta─│                       │──from_ap──►
                    └───────────────────────┘
```

**ACL Lists** (defined in `acl.h`):
| Index | Name | Direction | Description |
|-------|------|-----------|-------------|
| 0 | `to_sta` | STA inbound | Internet → ESP32 |
| 1 | `from_sta` | STA outbound | ESP32 → Internet |
| 2 | `to_ap` | AP inbound | Clients → ESP32 |
| 3 | `from_ap` | AP outbound | ESP32 → Clients |

**Data structure** (`acl.h`):
```c
typedef struct {
    uint32_t src;        // Source IP (pre-masked, network byte order)
    uint32_t s_mask;     // Source subnet mask
    uint32_t dest;       // Destination IP (pre-masked)
    uint32_t d_mask;     // Destination subnet mask
    uint16_t s_port;     // Source port (0 = any, TCP/UDP only)
    uint16_t d_port;     // Destination port (0 = any)
    uint8_t proto;       // Protocol: 0=any, 1=ICMP, 6=TCP, 17=UDP
    uint8_t allow;       // Action: ACL_DENY, ACL_ALLOW, or with ACL_MONITOR
    uint32_t hit_count;  // Packets matched by this rule
    uint8_t valid;       // Entry is active
} acl_entry_t;
```

**Action codes:**
- `ACL_DENY` (0x00) - Drop packet
- `ACL_ALLOW` (0x01) - Allow packet
- `ACL_MONITOR` (0x02) - Flag: also capture to PCAP
- `ACL_NO_MATCH` (0xFF) - No rule matched (packet allowed by default)

**Key functions** (`acl.c`):
- `acl_init()` - Initialize ACL subsystem
- `acl_add(acl_no, src, s_mask, dest, d_mask, proto, s_port, d_port, allow)` - Add rule
- `acl_delete(acl_no, rule_idx)` - Delete rule by index (compacts list)
- `acl_check_packet(acl_no, pbuf)` - Check packet against ACL, returns action
- `acl_clear(acl_no)` - Clear all rules from list
- `acl_parse_ip(str, &ip, &mask)` - Parse "192.168.1.0/24" or "any"
- `acl_format_ip(ip, mask, buf, len)` - Format IP with CIDR notation

**Rule processing:**
- Rules evaluated in order (first match wins)
- No match = packet allowed (permissive default)
- Non-IPv4 traffic (ARP, IPv6) passes without filtering
- Port filters only match TCP/UDP packets

**Storage:** Persisted in NVS as blobs under keys `"acl_0"` through `"acl_3"`

**Integration points:**
- Hooks called from `netif_input_hook()` and `netif_linkoutput_hook()` in `esp32_nat_router.c`
- Web interface at `/firewall` for rule management
- CLI commands via `cmd_router.c`

### Configuration Storage
All settings persist in NVS (Non-Volatile Storage) under namespace `esp32_nat`:
- WiFi credentials, static IP settings, port mappings, DHCP reservations
- Web interface password (`web_password` key) and disable state (`lock` key)
- Survives firmware updates (use `esptool.py erase_flash` for factory reset)

### Critical SDK Configuration
These settings in `sdkconfig.defaults` are required:
```
CONFIG_LWIP_IP_FORWARD=y    # Enable IP forwarding
CONFIG_LWIP_IPV4_NAPT=y     # Enable NAT (code won't compile without this)
CONFIG_LWIP_L2_TO_L3_COPY=y # LWIP layer support
```

## Serial Console Commands

Connect at 115200 bps. Key commands:
```
set_sta <ssid> <passwd>           # Set upstream WiFi
set_sta_static <ip> <subnet> <gw> # Static IP for STA
set_ap <ssid> <passwd>            # Configure AP hotspot
portmap add TCP <ext_port> <int_ip> <int_port>  # Add port mapping
portmap del TCP <ext_port>        # Delete port mapping
dhcp_reserve add <mac> <ip> [-n <name>]         # Add DHCP reservation
dhcp_reserve del <mac>            # Delete DHCP reservation
set_web_password <password>       # Set web interface password (empty to disable)
disable                           # Disable web interface completely
enable                            # Re-enable web interface
show status                       # Show router status (connection, clients, memory)
show config                       # Show router configuration (AP/STA settings)
show mappings                     # Show DHCP pool, reservations and port mappings
factory_reset                     # Erase all settings and restart (factory reset)
acl show [<list>]                 # Show ACL rules and statistics
acl add <list> <proto> <src> <sport> <dst> <dport> <action>  # Add ACL rule
acl del <list> <index>            # Delete ACL rule by index
acl clear <list>                  # Clear all rules from ACL list
```

## Web Interface

Access at `http://192.168.4.1` when connected to the AP.

**Pages:**
- `/` - System status (connection, IPs, clients, heap), login form, password management
- `/config` - Router configuration (AP/STA settings, static IP, MAC addresses) - protected
- `/mappings` - DHCP reservations and port forwarding management - protected
- `/firewall` - ACL firewall rules management (4 lists, add/delete rules, view stats) - protected

**Password Protection:**
- Optional password protects `/config` and `/mappings` pages
- Login form shown on index page when password is set
- Cookie-based sessions with 30-minute timeout
- Set via web interface or `set_web_password` command
- Empty password disables protection

**Session Management** (`http_server.c`):
- `create_session()` - Generate token and set cookie
- `is_authenticated()` - Validate session cookie and expiry
- `clear_session()` - Logout / invalidate session
- Session state stored in static variables (lost on reboot)

### Network Interface Hooks (Byte Counting)
The firmware hooks into the lwIP network interface to count bytes transmitted/received on the STA interface.

**How it works** (`esp32_nat_router.c`):
- Uses `esp_netif_get_netif_impl()` to access the underlying lwIP `struct netif`
- Saves original function pointers and installs custom hooks
- Hooks intercept packets, count bytes, then call original functions

**STA Interface Hooks (active):**
```c
// Original function pointer storage
static netif_input_fn original_netif_input;        // For received packets
static netif_linkoutput_fn original_netif_linkoutput;  // For sent packets

// Hook functions
netif_input_hook(pbuf, netif)      // Counts sta_bytes_received
netif_linkoutput_hook(netif, pbuf) // Counts sta_bytes_sent
```

**AP Interface Hooks (scaffolding for future use):**
```c
static netif_input_fn original_ap_netif_input;
static netif_linkoutput_fn original_ap_netif_linkoutput;

ap_netif_input_hook(pbuf, netif)      // Currently pass-through
ap_netif_linkoutput_hook(netif, pbuf) // Currently pass-through
```

**Public API** (`router_globals.h`):
- `init_byte_counter()` - Install STA hooks (called after WiFi init)
- `init_ap_netif_hooks()` - Install AP hooks (called during app_main)
- `get_sta_bytes_sent()` - Get total bytes sent via STA
- `get_sta_bytes_received()` - Get total bytes received via STA
- `reset_sta_byte_counts()` - Reset counters to zero

**Global counters:**
- `sta_bytes_sent` (uint64_t) - Total bytes sent through STA interface
- `sta_bytes_received` (uint64_t) - Total bytes received through STA interface

**Note:** Uses internal ESP-IDF API (`esp_netif_get_netif_impl`) which may change between versions.

## LED Status (GPIO 2)
- Solid on: Connected to upstream AP
- Solid off: Not connected
- Blinking: Number of blinks = connected device count
