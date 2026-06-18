/* WireGuard VPN settings and runtime state.
 *
 * SPDX-License-Identifier: MIT
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

// WireGuard VPN settings (persisted in NVS)
extern int32_t vpn_enabled;         // 0=off, 1=on
extern int32_t vpn_port;            // Peer UDP port (default 51820)
extern int32_t vpn_keepalive;       // Persistent keepalive seconds (0=disabled)
extern char* vpn_private_key;       // WireGuard private key (base64)
extern char* vpn_public_key;        // Peer public key (base64)
extern char* vpn_preshared_key;     // Preshared key (optional, base64)
extern char* vpn_endpoint;          // Peer endpoint host/IP
extern char* vpn_address;           // Tunnel IP (e.g. "10.0.0.2")
extern char* vpn_netmask;           // Tunnel netmask (e.g. "255.255.255.0")
extern char* vpn_dns;               // DNS server handed to AP clients while VPN is enabled (optional)
extern bool vpn_connected;          // Runtime state: tunnel is up
extern uint32_t vpn_tunnel_ip;      // Cached VPN tunnel IP (network byte order, 0 if not connected)
extern int32_t vpn_killswitch;      // Kill switch: block AP client internet when VPN is down (default on)
extern int32_t vpn_route_all;       // Route all traffic through VPN (1) or only VPN subnet (0, split tunnel)

// WireGuard VPN functions
esp_err_t vpn_connect(void);
void vpn_disconnect(void);
bool vpn_is_connected(void);
void vpn_connect_task(void *pvParameters);
void init_sntp_if_needed(void);

// VPN subnet helpers (for kill switch packet filtering)
void vpn_set_subnet(uint32_t ip, uint32_t mask);
bool vpn_in_subnet(uint32_t ip);

// Re-assert the WireGuard tunnel as lwIP's default route. Must be called after
// uplink GOT_IP / interface-up events, which make esp_netif reset netif_default
// to the uplink and would otherwise break route-all mode. No-op unless the VPN
// is connected with route_all enabled.
void vpn_reassert_default_route(void);

// Parse a standard WireGuard .conf file and persist the mapped vpn_* settings
// to NVS (sets vpn_enabled=1 on success). Returns ESP_ERR_INVALID_ARG if a
// required field (PrivateKey, PublicKey, Endpoint, Address) is missing.
esp_err_t vpn_import_conf(const char *text);

#ifdef __cplusplus
}
#endif
