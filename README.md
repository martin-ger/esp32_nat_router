# ESP32 NAT Router

This is a firmware to use the ESP32 as WiFi NAT router. It routes between the network of the AP interface and the STA or ETH interface as uplink network. It can also work as a VPN router using WireGuard as uplink.

**Use cases:**
- Simple range extender for an existing WiFi network
- An additional WiFi network with different SSID/password and restricted access for guests or IoT devices
- VPN-Router using WireGuard
- Converter from a corporate (WPA2-Enterprise) network to a regular (WPA-PSK) network for simple devices
- Classic WiFi router with Ethernet uplink
- MCP-server to control your network using agentic AI
- Presence detection and network monitoring in a Home Assistant IoT network
- Debugging and monitoring of WiFi devices

## Key Features

- **NAT Routing**: Full WiFi NAT router with IP forwarding (15+ Mbps throughput)
- **WireGuard VPN**: Optional VPN tunnel for upstream traffic with automatic MSS clamping and Path MTU
- **DHCP Reservations**: Assign fixed IPs to specific MAC addresses
- **Port Forwarding**: Map external ports to internal devices
- **Firewall**: Define ACL to restrict or monitor traffic
- **PCAP Capture**: Live packet capture can be streamed to Wireshark or other network tools
- **WPA2-Enterprise Support**: Connect to corporate networks (PEAP, TTLS, TLS) and convert them to WPA2-PSK
- **Ethernet Support**: Use a W32-ET01 board with LAN8720 PHY to get Ethernet uplink
- **Web Interface**: Web UI with password protection for easy configuration
- **Serial Console**: Full CLI for advanced configuration
- **Remote Console**: Network-accessible CLI via TCP (password protected, per-interface binding)
- **LED Status Indicator**: Visual feedback for connection and traffic status
- **OLED Display**: Status display on 72x40 I2C SSD1306 OLEDs (as found on some ESP32-C3 mini boards)
- **MQTT Home Assistant**: Publish telemetry and per-client stats to MQTT with HA auto-discovery
- **MCP Bridge (AI-Ready)**: BETA - Control the router from AI assistants (Claude, etc.) via the Model Context Protocol
- **OTA Updates**: Flash new firmware directly from the Web UI

The maximum number of simultaniously connected WiFi clients is 8 (5 on the ESP32c3) due to RAM limitations (uses about 5KB per client). Each of the features: Web Interface, PCAP Capture, Wireguard VPN, Remote Console, WPA Enterprise and MQTT Home Assistant require several KB of additional RAM. So using all of them at once will probably burst the ESP32's ressources. Have a look at remaining heap size if in doubt.

The code is originally based on the [Console Component](https://docs.espressif.com/projects/esp-idf/en/latest/api-guides/console.html#console) and the [esp-idf-nat-example](https://github.com/jonask1337/esp-idf-nat-example).

## First Boot

After first boot the ESP32 NAT Router will offer a WiFi network with an open AP and the ssid "ESP32_NAT_Router". Configuration can either be done via a web interface or via the serial console.

1. Connect to the **ESP32_NAT_Router** WiFi network
2. Open **http://192.168.4.1** in your browser
3. Configure your upstream WiFi and AP settings on the Getting Started page
4. Click **Save & Reboot**

<img src="https://raw.githubusercontent.com/martin-ger/esp32_nat_router/master/UI_Index.png">

## Flashing Pre-built Binaries

Install [esptool](https://github.com/espressif/esptool) and flash using the pre-built binaries from the `firmware_*` directories. Example for ESP32:

```bash
esptool.py --chip esp32 \
--before default_reset --after hard_reset write_flash \
-z --flash_mode dio --flash_freq 40m --flash_size detect \
0x1000 firmware_esp32/bootloader.bin \
0x8000 firmware_esp32/partition-table.bin \
0xf000 firmware_esp32/ota_data_initial.bin \
0x20000 firmware_esp32/esp32_nat_router.bin
```

Pre-built binaries are available for: **ESP32**, **ESP32-C3**, **ESP32-C6**, **ESP32-S3**, and **WT32-ETH01** (Ethernet).

See the [Installation](https://github.com/martin-ger/esp32_nat_router/wiki/Installation) wiki page for all chip-specific commands and the Flash Download Tool GUI.

## Documentation

Full documentation is available in the [Wiki](https://github.com/martin-ger/esp32_nat_router/wiki):

| Page | Description |
|------|-------------|
| [Web Interface](https://github.com/martin-ger/esp32_nat_router/wiki/Web-Interface) | Web UI pages, security, backup/restore |
| [WiFi and Network](https://github.com/martin-ger/esp32_nat_router/wiki/WiFi-and-Network) | DHCP reservations, port forwarding, WPA2-Enterprise, TTL, DNS |
| [Firewall](https://github.com/martin-ger/esp32_nat_router/wiki/Firewall) | ACL packet filtering rules and configuration |
| [Packet Capture](https://github.com/martin-ger/esp32_nat_router/wiki/Packet-Capture) | PCAP streaming to Wireshark |
| [WireGuard VPN](https://github.com/martin-ger/esp32_nat_router/wiki/WireGuard-VPN) | VPN tunnel configuration and server setup |
| [Remote Console](https://github.com/martin-ger/esp32_nat_router/wiki/Remote-Console) | Network-accessible CLI via TCP |
| [MQTT Home Assistant](https://github.com/martin-ger/esp32_nat_router/wiki/MQTT-Home-Assistant) | MQTT telemetry with HA auto-discovery |
| [MCP Bridge](https://github.com/martin-ger/esp32_nat_router/wiki/MCP-Bridge) | AI assistant integration via Model Context Protocol |
| [CLI Reference](https://github.com/martin-ger/esp32_nat_router/wiki/CLI-Reference) | Full command listing for the serial/remote console |
| [Hardware](https://github.com/martin-ger/esp32_nat_router/wiki/Hardware) | LED status, OLED display, antenna switch, factory reset |
| [WT32-ETH01](https://github.com/martin-ger/esp32_nat_router/wiki/WT32-ETH01) | Ethernet uplink variant (LAN8720 PHY) |
| [Installation](https://github.com/martin-ger/esp32_nat_router/wiki/Installation) | Flashing pre-built binaries |
| [Building](https://github.com/martin-ger/esp32_nat_router/wiki/Building) | Compiling from source with ESP-IDF or PlatformIO |

## Building from Source

```bash
idf.py menuconfig    # Enable LWIP IP forwarding, NAT, and L2-to-L3 copy
idf.py build
idf.py flash monitor
```

See the [Building](https://github.com/martin-ger/esp32_nat_router/wiki/Building) wiki page for PlatformIO, WT32-ETH01, and multi-target build instructions.

## Licence

The WireGuard submodul has the following licence_
```
Copyright (c) 2021 Kenta Ida (fuga@fugafuga.org)

The original license is below:
Copyright (c) 2021 Daniel Hope (www.floorsense.nz)
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:
* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright notice, this
  list of conditions and the following disclaimer in the documentation and/or
  other materials provided with the distribution.
* Neither the name of "Floorsense Ltd", "Agile Workspace Ltd" nor the names of
  its contributors may be used to endorse or promote products derived from this
  software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

Author: Daniel Hope <daniel.hope@smartalock.com>
```
