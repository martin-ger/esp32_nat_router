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

### Flash Pre-built Binaries
```bash
# ESP32:
esptool.py --chip esp32 --before default_reset --after hard_reset write_flash \
  -z --flash_mode dio --flash_freq 40m --flash_size detect \
  0x1000 build/esp32/bootloader.bin \
  0x8000 build/esp32/partitions.bin \
  0x10000 build/esp32/firmware.bin

# ESP32-C3:
esptool.py --chip esp32c3 --before default_reset --after hard_reset write_flash \
  -z --flash_size detect \
  0x0 build/esp32c3/bootloader.bin \
  0x8000 build/esp32c3/partitions.bin \
  0x10000 build/esp32c3/firmware.bin
```

## Architecture

### Source Structure
```
main/
├── esp32_nat_router.c   # Entry point: WiFi init, event handling, LED status, port mapping
├── http_server.c        # Web UI server at 192.168.4.1
├── pages.h              # HTML/CSS for web interface
└── cmd_decl.h           # Command declarations

components/
├── cmd_router/          # CLI commands: set_sta, set_ap, portmap, show
├── cmd_system/          # System commands: free, heap, restart, tasks
└── cmd_nvs/             # NVS storage commands: nvs_set, nvs_get, nvs_erase
```

### Key Global Variables (in router_globals.h)
- `ssid`, `passwd` - Upstream WiFi credentials
- `ap_ssid`, `ap_passwd` - Access point credentials
- `static_ip`, `subnet_mask`, `gateway_addr` - Static IP config
- `my_ip`, `my_ap_ip` - Current IP addresses
- `portmap_tab[]` - Port mapping table
- `ap_connect` - AP connection status flag
- `connect_count` - Number of connected clients

### Configuration Storage
All settings persist in NVS (Non-Volatile Storage) under namespace `esp32_nat`:
- WiFi credentials, static IP settings, port mappings
- Web interface lock state
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
show                              # Display current config
```

## LED Status (GPIO 2)
- Solid on: Connected to upstream AP
- Solid off: Not connected
- Blinking: Number of blinks = connected device count
