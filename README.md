# ESP32 NAT Router with WPA2 Enterprise support

This is a firmware to use the ESP32 as WiFi NAT router. It can be used as:
- Simple range extender for an existing WiFi network
- Setting up an additional WiFi network with different SSID/password for guests or IOT devices
- Convert a corporate (WPA2-Enterprise) network to a regular network, for simple devices

## Key Features

- **NAT Routing**: Full WiFi NAT router with IP forwarding (15+ Mbps throughput)
- **DHCP Reservations**: Assign fixed IPs to specific MAC addresses
- **Port Forwarding**: Map external ports to internal devices
- **WPA2-Enterprise Support**: Connect to corporate networks and convert them to WPA2-PSK
- **Web Interface**: Modern web UI at 192.168.4.1 for easy configuration
- **Connected Clients Display**: View all connected devices with MAC, IP, and device names
- **Password Protection**: Optional password protection for web interface configuration pages
- **PCAP Capture**: Live packet capture streamed to Wireshark via TCP
- **Static IP Support**: Configure static IP for the STA (upstream) interface
- **Serial Console**: Full CLI for advanced configuration
- **Persistent Storage**: All settings stored in NVS, survive firmware updates
- **LED Status Indicator**: Visual feedback for connection status and connected clients
It can achieve a bandwidth of more than 15mbps.

The code is originally based on the [Console Component](https://docs.espressif.com/projects/esp-idf/en/latest/api-guides/console.html#console) and the [esp-idf-nat-example](https://github.com/jonask1337/esp-idf-nat-example). 

## First Boot
After first boot the ESP32 NAT Router will offer a WiFi network with an open AP and the ssid "ESP32_NAT_Router". Configuration can either be done via a simple web interface or via the serial console. 

## Web Config Interface
The web interface allows for the configuration of all parameters. Connect your PC or smartphone to the WiFi SSID "ESP32_NAT_Router" and point your browser to "http://192.168.4.1" (or later the configured AP IP address).

The web interface consists of three pages:

### System Status Page (/)
The main dashboard displays:
- Current connection status and uptime
- STA (upstream) and AP IP addresses and MAC addresses
- Used IP pool for DHCP
- Number of connected clients
- Bytes sent and received
- PCAP capture status (when enabled: captured/dropped packet counts)

<img src="https://raw.githubusercontent.com/martin-ger/esp32_nat_router/master/UI_Index.png">

### Configuration Page (/config)
Configure all router settings:
- **Access Point Settings**: Configure the ESP32's access point name, password, IP address (default: 192.168.4.1), and MAC address
- **Station Settings (Uplink)**: Enter the SSID and password for the upstream WiFi network (leave password blank for open networks), with optional WPA2-Enterprise credentials and MAC address customization
- **Static IP Settings**: Optionally configure a static IP for the STA (upstream) interface
- **PCAP Packet Capture**: Enable/disable packet capture and configure snaplen (max bytes per packet)
- **Device Management**: Reboot the device
- Click "Apply", "Connect", or "Set Static IP" to apply changes (the ESP32 will reboot)

<img src="https://raw.githubusercontent.com/martin-ger/esp32_nat_router/master/UI_Settings.png">

Be aware that changes to AP settings (including the AP IP address) also affect the config interface itself - after changing the AP IP address, reconnect to the ESP32 at the new IP address to continue configuration. Also all currently defined DHCP reservations and port forwards will be deleted.

### Mappings Page (/mappings)
Manage network mappings:
- **Connected Clients**: Shows all currently connected clients with MAC, IP, and optially name.
- **DHCP Reservations**: Assign fixed IP addresses to specific MAC addresses (useful for servers/devices that need consistent IPs). Make sure you assign port numbers in the range of the DHCP pool.
- **Port Forwarding**: Create port mappings to access devices behind the NAT router (e.g., `TCP 8080 -> 192.168.4.2:80`)

<img src="https://raw.githubusercontent.com/martin-ger/esp32_nat_router/master/UI_Mappings.png">

### Web Interface Security

The web interface is visible on both interfaces (AP and STA) and allows configuration access to all parameters. Two security mechanisms are available:

#### Password Protection

You can protect the `/config` and `/mappings` pages with a password. The main status page (`/`) remains accessible but will show a login form.

**Setting a Password (Web Interface):**
- On the main page (`/`), scroll to the "Set Password" section
- Enter and confirm your new password
- Click "Set Password"
- The page will reload and show a login form

**Setting a Password (Serial Console):**
```
set_web_password mypassword
```

To disable password protection, set an empty password:
```
set_web_password ""
```

When password protection is enabled:
- The main page shows system status and a login form
- After successful login, you can access `/config` and `/mappings`
- Sessions expire after 30 minutes of inactivity
- A "Logout" button appears on all pages when logged in

#### Disabling the Web Interface

For maximum security in open environments, you can completely disable the web interface:

**From the Web Interface:**
- Navigate to the `/config` page
- Scroll to the "Danger Zone" section at the bottom
- Click "Disable" button
- Confirm the warning dialog
- The device will reboot with the web interface disabled

**From the Serial Console:**
```
disable
```

After disabling, the web interface will be completely inaccessible. Re-enable it via the serial console with:
```
enable
```

If you made a mistake and have lost all contact with the ESP you can still use the serial console to reconfigure it. All parameter settings are stored in NVS (non volatile storage), which is *not* erased by simple re-flashing the binaries. If you want to wipe it out, use "esptool.py -p /dev/ttyUSB0 erase_flash".

## Access devices behind the router

If you want to access a device behind the esp32 NAT router: `PC -> local router -> esp32NAT -> server`

### DHCP Reservations
To ensure devices behind the router always get the same IP address, you can configure DHCP reservations:

```
dhcp_reserve add AA:BB:CC:DD:EE:FF 192.168.4.10 -n MyServer
                                                    ↑ optional friendly name
                                   ↑ reserved IP address
                 ↑ device MAC address
```

This is useful for servers or IoT devices that other devices need to connect to reliably.

### Port Forwarding
Let's say "server" is exposing a webserver on port 80 and you want to access that from your PC outside the NAT network.
For that you need to configure a port mapping (via the web interface at `/mappings` or the serial console):

```
portmap add TCP 8080 192.168.4.2 80
                                 ↑ port of the webserver
                            ↑ server's ip in esp32NAT network
                  ↑ exposed port in the local router's network
```

Assuming the esp32NAT's IP address in your `local router` is `192.168.0.57`, you can access the server by typing `192.168.0.57:8080` into your browser.

## PCAP Packet Capture

The router includes a built-in packet capture feature that streams AP interface traffic to Wireshark in real-time via TCP.

### Quick Start

1. Enable capture via the web interface (`/config` page) or serial console:
```
pcap start
```

2. Connect Wireshark from your computer:
```bash
nc 192.168.4.1 19000 | wireshark -k -i -
```

Or configure Wireshark directly:
- Go to Capture > Options > Manage Interfaces > Pipes
- Add new pipe: `TCP@192.168.4.1:19000`

### Web Interface

On the **Configuration page** (`/config`), the PCAP Packet Capture section allows you to:
- View current capture status (On/Off)
- Enable or disable capture with a single click
- Set the snaplen value (64-1600 bytes)

The **System Status page** (`/`) shows the current capture state and, when enabled, displays the number of captured and dropped packets.

### Console Commands

```
pcap start           # Enable packet capture
pcap stop            # Disable packet capture
pcap status          # Show capture statistics
pcap snaplen         # Show current snaplen (bytes per packet)
pcap snaplen 1500    # Set snaplen (64-1600 bytes)
```

### Example Status Output

```
PCAP Capture Status:
====================
Capture:  enabled
Client:   connected
Snaplen:  512 bytes
Buffer:   4096 / 32768 bytes (12.5%)
Captured: 1523 packets
Dropped:  0 packets

Connection: nc <esp32_ip> 19000 | wireshark -k -i -
```

### Technical Details

- **TCP Port**: 19000
- **Buffer Size**: 32KB ring buffer
- **Default Snaplen**: 512 bytes (configurable 64-1600)
- **Format**: Standard PCAP with DLT_EN10MB (Ethernet)
- **Single Client**: One Wireshark connection at a time
- **AP Traffic Only**: Captures packets to/from WiFi clients connected to the ESP32

### Tips

- Use a smaller snaplen (e.g., 128) to capture more packets in the buffer if you only need headers
- Use a larger snaplen (e.g., 1500) to capture full packet contents
- Check `pcap status` to monitor for dropped packets (buffer overflow)
- Capture is automatically paused when no client is connected to save CPU

## Firewall (ACL)

The router includes a stateless packet filtering firewall with four Access Control Lists (ACLs), one for each traffic direction.

### Network Topology

```
                              ESP32 NAT Router
                        ┌───────────────────────┐
                        │                       │
   Internet ◄──────────►│  STA            AP    │◄──────────► Internal
  (Upstream)            │  Interface  Interface │              Clients
                        │                       │
                        └───────────────────────┘
```

### ACL Naming Convention

ACLs are named from the perspective of each interface - "to" means traffic arriving at the interface, "from" means traffic leaving the interface:

```
                              ESP32
                        ┌───────────────────────┐
                        │                       │
   Internet ──to_sta───►│  STA            AP    │◄───to_ap─── Clients
            ◄──from_sta─│                       │───from_ap──►
                        │                       │
                        └───────────────────────┘
```

| ACL | Interface | Direction | Description |
|-----|-----------|-----------|-------------|
| **to_sta** | STA | Inbound | Internet → ESP32 (traffic arriving at STA interface) |
| **from_sta** | STA | Outbound | ESP32 → Internet (traffic leaving STA interface) |
| **to_ap** | AP | Inbound | Clients → ESP32 (traffic arriving at AP interface) |
| **from_ap** | AP | Outbound | ESP32 → Clients (traffic leaving AP interface) |

### Use Cases

- **to_sta**: Block unwanted incoming traffic from the Internet
- **from_sta**: Control what internal clients can access on the Internet
- **to_ap**: Filter traffic from specific internal clients
- **from_ap**: Control what traffic reaches internal clients

### Web Interface

Access the firewall configuration at `/firewall`. For each ACL you can:
- Add rules with source/destination IP (CIDR notation), protocol, ports, and action
- Enable monitoring to capture matching packets to PCAP
- View hit counters and statistics
- Delete individual rules or clear entire lists

### Console Commands

```
acl show [<list>]                    # Show rules and stats
acl add <list> <proto> <src> <sport> <dst> <dport> <action>
acl del <list> <index>               # Delete rule by index
acl clear <list>                     # Clear all rules
```

**Examples:**
```
# Block incoming traffic from a specific IP
acl add to_sta IP 203.0.113.50 * any * deny

# Allow only DNS and HTTP/HTTPS from clients to Internet
acl add to_ap UDP any * any 53 allow
acl add to_ap TCP any * any 80 allow
acl add to_ap TCP any * any 443 allow
acl add from_sta IP any * any * deny
```

### Rule Processing

- Rules are evaluated in order (first match wins)
- If no rule matches, the packet is **allowed** (permissive default)
- Non-IPv4 traffic (ARP, IPv6) passes through without filtering
- Port filters only apply to TCP/UDP packets; rules with port filters won't match ICMP or other protocols
- Rules persist in NVS storage

### ACL Actions and PCAP Capture

Each rule can have one of four actions:

| Action | Packet | Captured to PCAP |
|--------|--------|------------------|
| `allow` | ✅ Allowed | ❌ No |
| `deny` | ❌ Dropped | ❌ No |
| `allow_monitor` | ✅ Allowed | ✅ Yes |
| `deny_monitor` | ❌ Dropped | ✅ Yes (before drop) |

**PCAP capture behavior:**

- **AP interface** (client traffic): Captured automatically when PCAP is enabled
- **STA interface** (Internet traffic): Only captured when a `+monitor` rule matches

The STA interface is intentionally not captured by default to avoid a feedback loop - the PCAP stream itself is sent over the STA interface to Wireshark, so capturing all STA traffic would capture the PCAP stream itself.

**Use cases for monitor rules:**

```
# Capture all DNS queries going to the Internet (for debugging)
acl add from_sta UDP any * any 53 allow_monitor

# Capture specific client's traffic without blocking
acl add to_ap IP 192.168.4.100 * any * allow_monitor
```

## LED Status Indicator

The on-board LED provides visual feedback about connection status:
- **LED on**: ESP32 is connected to the upstream AP
- **LED off**: ESP32 is not connected to upstream
- **Blinking**: Number of blinks indicates the number of connected clients

For example:

One device connected to the ESP32, and the ESP32 is connected to upstream:

`*****.*****`

Two devices are connected to the ESP32, but the ESP32 is not connected to upstream:

`....*.*....`

### Configuring the LED GPIO

By default, the LED is **disabled**. To enable it, configure the GPIO pin for your board:

```
set_led_gpio 2          # Set LED to GPIO 2
set_led_gpio none       # Disable LED (default)
set_led_gpio            # Show current setting
```

Changes take effect after restart.

### Common LED GPIO Pins by Board

| Board / Chip | Default LED GPIO |
|--------------|------------------|
| ESP32 DevKit v1 / WROOM | GPIO 2 |
| ESP32-S2 | GPIO 2 (varies) |
| ESP32-S3 DevKitC | GPIO 48 (RGB) |
| ESP32-C3 DevKitM / SuperMini | GPIO 8 |
| ESP32-C6 DevKitC | GPIO 8 |
| NodeMCU-32S | GPIO 2 |
| Lolin D32 | GPIO 5 |
| Lolin32 Lite | GPIO 22 |

**Note**: Some boards have active-low LEDs. ESP32-S3 often uses GPIO 48 for an addressable RGB LED (WS2812) which may require different handling.

# Command Line Interface

For configuration you have to use a serial console (Putty or GtkTerm with 115200 bps).
Use the "set_sta" and the "set_ap" command to configure the WiFi settings. Changes are stored persistently in NVS and are applied after next restart. Use "show" to display the current config. The NVS namespace for the parameters is "esp32_nat"

Enter the `help` command get a full list of all available commands:
```
help 
  Print the list of registered commands

free 
  Get the current size of free heap memory

heap 
  Get minimum size of free heap memory that was available during program execu
  tion

version 
  Get version of chip and SDK

restart
  Software reset of the chip

factory_reset
  Erase all settings (NVS namespace 'esp32_nat') and restart

deep_sleep  [-t <t>] [--io=<n>] [--io_level=<0|1>]
  Enter deep sleep mode. Two wakeup modes are supported: timer and GPIO. If no
  wakeup option is specified, will sleep indefinitely.
  -t, --time=<t>  Wake up time, ms
      --io=<n>  If specified, wakeup using GPIO with given number
  --io_level=<0|1>  GPIO level to trigger wakeup

light_sleep  [-t <t>] [--io=<n>]... [--io_level=<0|1>]...
  Enter light sleep mode. Two wakeup modes are supported: timer and GPIO. Mult
  iple GPIO pins can be specified using pairs of 'io' and 'io_level' arguments
  . Will also wake up on UART input.
  -t, --time=<t>  Wake up time, ms
      --io=<n>  If specified, wakeup using GPIO with given number
  --io_level=<0|1>  GPIO level to trigger wakeup

tasks 
  Get information about running tasks

nvs_set  <key> <type> -v <value>
  Set key-value pair in selected namespace.
Examples:
 nvs_set VarName i32 -v 
  123 
 nvs_set VarName str -v YourString 
 nvs_set VarName blob -v 0123456789abcdef 
         <key>  key of the value to be set
        <type>  type can be: i8, u8, i16, u16 i32, u32 i64, u64, str, blob
  -v, --value=<value>  value to be stored

nvs_get  <key> <type>
  Get key-value pair from selected namespace. 
Example: nvs_get VarName i32
         <key>  key of the value to be read
        <type>  type can be: i8, u8, i16, u16 i32, u32 i64, u64, str, blob

nvs_erase  <key>
  Erase key-value pair from current namespace
         <key>  key of the value to be erased

nvs_namespace  <namespace>
  Set current namespace
   <namespace>  namespace of the partition to be selected

nvs_list  <partition> [-n <namespace>] [-t <type>]
  List stored key-value pairs stored in NVS.Namespace and type can be specified
  to print only those key-value pairs.
  
Following command list variables stored inside 'nvs' partition, under namespace 'storage' with type uint32_t
  Example: nvs_list nvs -n storage -t u32 

   <partition>  partition name
  -n, --namespace=<namespace>  namespace name
  -t, --type=<type>  type can be: i8, u8, i16, u16 i32, u32 i64, u64, str, blob

nvs_erase_namespace  <namespace>
  Erases specified namespace
   <namespace>  namespace to be erased

set_sta  <ssid> <passwd>
  Set SSID and password of the STA interface
        <ssid>  SSID
      <passwd>  Password
  --, -u, ----username=<ent_username>  Enterprise username
  --, -a, ----anan=<ent_identity>  Enterprise identity

set_sta_static  <ip> <subnet> <gw>
  Set Static IP for the STA interface
          <ip>  IP
      <subnet>  Subnet Mask
          <gw>  Gateway Address

set_ap  <ssid> <passwd>
  Set SSID and password of the SoftAP
        <ssid>  SSID of AP
      <passwd>  Password of AP

set_ap_ip  <ip>
  Set IP for the AP interface
          <ip>  IP

portmap  [add|del] [TCP|UDP] <ext_portno> <int_ip> <int_portno>
  Add or delete a portmapping to the router
     [add|del]  add or delete portmapping
     [TCP|UDP]  TCP or UDP port
  <ext_portno>  external port number
      <int_ip>  internal IP
  <int_portno>  internal port number

dhcp_reserve  [add|del] <mac> <ip> [-n <name>]
  Add or delete a DHCP reservation (fixed IP for a MAC address)
     [add|del]  add or delete reservation
         <mac>  MAC address (format: AA:BB:CC:DD:EE:FF)
          <ip>  IP address to reserve
  -n, --name=<name>  Optional device name

disable
  Disable the web interface

enable
  Enable the web interface

set_web_password  <password>
  Set web interface password (empty string ("") to disable)
      <password>  Password for web interface login

show  [status|config|mappings]
  Show router status, config or mappings

bytes  [[reset]]
  Show or reset STA interface byte counts

pcap  <action> [<bytes>]
  Control PCAP packet capture (TCP port 19000)
      <action>  start|stop|status|snaplen
       <bytes>  snaplen value (64-1600)

set_led_gpio  [<gpio>|none]
  Set GPIO for status LED blinking
       <gpio>  GPIO pin number (0-48), or 'none' to disable
               Without arguments, shows current setting

```

If you want to enter non-ASCII or special characters (incl. ' ') you can use HTTP-style hex encoding (e.g. "My%20AccessPoint" results in a string "My AccessPoint").

## Set console output to UART or USB_SERIAL_JTAG (USB-OTG)
All newer ESP32 boards have a built in [USB Serial/JTAG Controller](https://docs.espressif.com/projects/esp-idf/en/latest/esp32c3/api-guides/usb-serial-jtag-console.html). 
If the USB port is connected directly to the USB Serial/JTAG Controller, you wont be able to use the console over UART.

You can change the console output to USB_SERIAL_JTAG:

**Menuconfig:**
`Component config` -> `ESP System Settings` -> `Channel for console output` -> `USB Serial/JTAG Controller`

**Changing sdkconfig directly**
```
CONFIG_ESP_CONSOLE_UART_DEFAULT=n
CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG=y
```

[Board comparison list](https://docs.espressif.com/projects/esp-idf/en/v5.0.4/esp32/hw-reference/chip-series-comparison.html)

## Flashing the Pre-built Binaries

### Using esptool

Get and install [esptool](https://github.com/espressif/esptool):

```
cd ~
python3 -m pip install pyserial
git clone https://github.com/espressif/esptool
cd esptool
python3 setup.py install
```

### Flashing Instructions

Go to esp32_nat_router project directory and use the prebuild binary artifacts from the `firmware_*` directories.

For ESP32:

```bash
esptool.py --chip esp32 \
--before default_reset --after hard_reset write_flash \
-z --flash_mode dio --flash_freq 40m --flash_size detect \
0x1000 firmware_esp32/bootloader.bin \
0x8000 firmware_esp32/partition-table.bin \
0x10000 firmware_esp32/esp32_nat_router.bin
```

For ESP32-C2:

```bash
esptool.py --chip esp32c2 \
--before default_reset --after hard_reset write_flash \
-z --flash_size detect \
0x0 firmware_esp32c2/bootloader.bin \
0x8000 firmware_esp32c2/partition-table.bin \
0x10000 firmware_esp32c2/esp32_nat_router.bin
```

For ESP32-C3:

```bash
esptool.py --chip esp32c3 \
--before default_reset --after hard_reset write_flash \
-z --flash_size detect \
0x0 firmware_esp32c3/bootloader.bin \
0x8000 firmware_esp32c3/partition-table.bin \
0x10000 firmware_esp32c3/esp32_nat_router.bin
```

For ESP32-S3:

```bash
esptool.py --chip esp32s3 \
--before default_reset --after hard_reset write_flash \
-z --flash_size detect \
0x0 firmware_esp32s3/bootloader.bin \
0x8000 firmware_esp32s3/partition-table.bin \
0x10000 firmware_esp32s3/esp32_nat_router.bin
```

### Available Artifacts

Each `firmware_*` directory contains:

- **`esp32_nat_router.bin`** - Main application firmware
- **`bootloader.bin`** - ESP32 bootloader
- **`partition-table.bin`** - Partition table
- **`build_info.txt`** - Build metadata (timestamp, git hash, target)

As an alternative you might use [Espressif's Flash Download Tools](https://www.espressif.com/en/products/hardware/esp32/resources) with the parameters given in the figure below (thanks to mahesh2000), update the filenames accordingly:

![image](https://raw.githubusercontent.com/martin-ger/esp32_nat_router/master/FlasherUI.jpg)

## Building the Binaries 
### Method 1 - ESP-IDF
The following are the steps required to compile this project:

1. Download and setup the ESP-IDF.

2. In the project directory run `make menuconfig` (or `idf.py menuconfig` for cmake).
    1. *Component config -> LWIP > [x] Enable copy between Layer2 and Layer3 packets.
    2. *Component config -> LWIP > [x] Enable IP forwarding.
    3. *Component config -> LWIP > [x] Enable NAT (new/experimental).
3. Build the project and flash it to the ESP32.

A detailed instruction on how to build, configure and flash a ESP-IDF project can also be found the official ESP-IDF guide. 

### Method 2 - Platformio
The following are the steps required to compile this project:

1. Download Visual Studio Code, and the Platform IO extension.
2. In Platformio, install the ESP-IDF framework.
3. Build the project and flash it to the ESP32.

### Multi-Target Build Scripts

For automated building across multiple ESP32 targets with esp-idf, use the provided build scripts:

```bash
./build_all_targets.sh
```

## DNS
As soon as the ESP32 STA has learned a DNS IP from its upstream DNS server on first connect, it passes that to newly connected clients.
Before that by default the DNS-Server which is offerd to clients connecting to the ESP32 AP is set to 8.8.8.8.
Replace the value of the *MY_DNS_IP_ADDR* with your desired DNS-Server IP address (in hex) if you want to use a different one.

## Performance

All tests used `IPv4` and the `TCP` protocol.

| Board | Tools | Optimization | CPU Frequency | Throughput | Power |
| ----- | ----- | ------------ | ------------- | ---------- | ----- |
| `ESP32D0WDQ6` | `iperf3` | `0g` | `240MHz` | `16.0 MBits/s` | `1.6 W` |
| `ESP32D0WDQ6` | `iperf3` | `0s` | `240MHz` | `10.0 MBits/s` | `1.8 W` | 
| `ESP32D0WDQ6` | `iperf3` | `0g` | `160MHz` | `15.2 MBits/s` | `1.4 W` |
| `ESP32D0WDQ6` | `iperf3` | `0s` | `160MHz` | `14.1 MBits/s` | `1.5 W` |

