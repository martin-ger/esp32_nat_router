# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

ESP-IDF (5.5.x) firmware that turns an ESP32 into a WiFi NAT router: AP interface downstream, WiFi STA or Ethernet (LAN8720) upstream, optional WireGuard uplink. Configured via web UI, serial console, remote TCP console, and an MCP bridge. User docs live in the GitHub wiki; a local copy is in `wiki/` (untracked here, published separately).

## Build

ESP-IDF environment must be sourced first (`. $IDF_PATH/export.sh`).

```bash
idf.py build                       # default target from ./sdkconfig
idf.py flash monitor

# Single variant, same layout the release script uses:
idf.py -B build_eth -D SDKCONFIG=sdkconfig.eth \
  -D SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.defaults.eth_common;sdkconfig.defaults.wt32_eth01" build

./build_all_targets.sh             # all 7 variants, clean builds, copies to firmware_*/
```

- Variants: `esp32`, `esp32s3`, `esp32c3`, `esp32c5`, `esp32c6` (WiFi uplink) and `wt32_eth01`, `esp32_poe_iso` (Ethernet uplink, chip esp32). Each has its own `build_<x>/` dir and `sdkconfig.<x>` file; the mapping is in `build_all_targets.sh`.
- `sdkconfig*` (except `sdkconfig.defaults*`) and `build*/` are gitignored — change defaults in `sdkconfig.defaults*`, not in generated sdkconfig files.
- No test suite; verification is building the affected targets and testing on hardware.
- **Flash budget:** the app must fit `ota_0` (1536 KiB, `partitions_example.csv`). C3/C5 are close to the limit; the build script warns above 95%. Check `idf.py size-components` when adding code.

## Releases

- Version is `PROJECT_VER` in the top-level `CMakeLists.txt`; also bump `version` in `manifest_*.json` (web installer).
- `firmware_*/` hold committed release binaries produced by `build_all_targets.sh`. Don't touch them in normal code commits; they're regenerated in separate "firmware build" commits.

## Architecture

- `main/esp32_nat_router.c` — `app_main`, NVS/console init, WiFi/ETH init and event handlers, STA reconnect logic, LED status thread, antenna switch.
- `main/netif_hooks.c` — **the packet hot path.** Wraps lwIP `netif->input`/`linkoutput` of the uplink and AP netifs for byte counting, per-client stats, ACL, PCAP, TTL rewrite, MSS clamping, Path MTU (ICMP Frag Needed), VPN kill switch. Keep it fast: `IRAM_ATTR`, no logging/allocation per packet, compiled `-O2` while the rest of `main` is `-Os` (see `main/CMakeLists.txt`).
- `main/portmap.c`, `dhcp_manager.c` (DHCP reservations), `vpn_manager.c` (WireGuard via the `esp_wireguard` managed component), `led_strip_status.c` (C5 uses a bit-bang WS2812 driver; other targets use `espressif/led_strip`).
- `components/`:
  - `cmd_router` — almost all console commands, plus the NVS accessors `get/set_config_param_{str,int,blob}` (declared in `include/wifi_config.h`).
  - `cmd_system` — system commands (heap, tasks, restart, …).
  - `http_server` — web UI. Pages are C string macros in `pages/page_*.h`, streamed in chunks; handlers and `/api/*` endpoints (config export/import, VPN import, OTA upload) in `http_server.c`.
  - `acl` (firewall), `pcap_capture` (ring buffer + TCP stream on port 19000), `remote_console` (TCP CLI, default 2323), `dhcpserver` (patched copy of the lwIP/IDF DHCP server), `mqtt_ha`, `oled_display`, `syslog`.
- `include/` — shared headers across main and components (`router_config.h` has global tuning vars and `AP_MAX_CONNECTIONS`, which is 5 on C3/C5 and 8 elsewhere).
- `esp_nat_bridge.py` — MCP server (fastmcp + telnetlib3) that drives the router through the remote console and **parses console output with regexes**. If you change the text of a console command's output, update the bridge too.

### Build-time configuration
- `CONFIG_ETH_UPLINK` vs `CONFIG_WIFI_STA_UPLINK` (Kconfig `main/Kconfig.projbuild`) selects the uplink; code uses `#if CONFIG_ETH_UPLINK` with `ethNetif` vs `wifiSTA`. Changes to uplink handling must compile in both modes.
- Per-chip differences use `CONFIG_IDF_TARGET_*` (e.g. 5 GHz band selection only on C5, mDNS not on C5).

### Configuration storage
- All settings live in NVS namespace `esp32_nat` (`PARAM_NAMESPACE`). Keys are ≤15 chars.
- A new setting usually needs: NVS key + console command in `cmd_router.c` + web UI field + `wiki/NVS-Storage.md` and `wiki/CLI-Reference.md` entries (and the MCP bridge if it should be exposed there).
- Config export (`nvs_export_to_json_robust` in `http_server.c`) dumps every key; secrets are excluded from plaintext exports by an explicit list — add any new credential key there.

## Conventions and gotchas

- RAM is the tightest resource. Features are off by default and must allocate nothing when disabled.
- lwIP state (netif list, routes, NAPT) is not safe to walk from console or HTTP tasks (no core locking); snapshot it on the tcpip thread via `esp_netif_tcpip_exec` (see `show routes` in `cmd_router.c`).
- Stack sizes are tuned (main 7168, sys_evt 4096 in `sdkconfig.defaults`); `ESP_LOG` in event handlers is expensive on stack. Be careful adding large locals in callbacks.
- Web UI output must HTML-escape user-controlled strings (SSIDs, hostnames, etc.) with `html_escape()` in `http_server.c`; passwords must never be echoed back into pages.
- Commit messages are short, often reference the GitHub issue (`- issue #276`).
