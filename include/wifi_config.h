/* WiFi credential externs, AP/STA config, NVS helpers, and set_sta/set_ap.
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

/* 5 GHz band support — currently only ESP32-C5 has dual-band WiFi */
#if defined(CONFIG_IDF_TARGET_ESP32C5)
#define WIFI_HAS_5GHZ 1
#else
#define WIFI_HAS_5GHZ 0
#endif

/* STA band preference (only meaningful when WIFI_HAS_5GHZ) */
#define STA_BAND_AUTO  0   /* Connect to strongest signal regardless of band */
#define STA_BAND_2G    1   /* Prefer 2.4 GHz (channels 1-14) */
#define STA_BAND_5G    2   /* Prefer 5 GHz (channels > 14) */

#if WIFI_HAS_5GHZ
extern uint8_t sta_band;   /* STA_BAND_AUTO / STA_BAND_2G / STA_BAND_5G */
#endif

#if !CONFIG_ETH_UPLINK
extern char* ssid;
extern char* ent_username;
extern char* ent_identity;
extern char* passwd;
#endif
extern char* static_ip;
extern char* subnet_mask;
extern char* gateway_addr;
extern char* ap_ssid;
extern char* ap_passwd;
extern char* ap_dns;
extern char* hostname;

extern uint16_t connect_count;
extern bool ap_connect;
extern bool wifi_scan_active;

extern uint32_t my_ip;
extern uint32_t my_ap_ip;

// AP SSID hidden (0 = visible, 1 = hidden)
extern uint8_t ap_ssid_hidden;

// AP auth mode (0 = WPA2/WPA3, 1 = WPA2 only, 2 = WPA3 only)
extern uint8_t ap_authmode;

#if CONFIG_ETH_UPLINK
// AP WiFi channel (0 = auto, 1-13 = fixed channel; ETH_UPLINK only)
extern uint8_t ap_channel;
#endif

#if !CONFIG_ETH_UPLINK
// WPA2-Enterprise settings
extern int32_t eap_method;          // 0=Auto, 1=PEAP, 2=TTLS, 3=TLS
extern int32_t ttls_phase2;         // 0=MSCHAPv2, 1=MSCHAP, 2=PAP, 3=CHAP
extern int32_t use_cert_bundle;     // 0=off, 1=on
extern int32_t disable_time_check;  // 0=off, 1=on
#endif

void preprocess_string(char* str);
#if !CONFIG_ETH_UPLINK
int set_sta(int argc, char **argv);
int set_sta_mac(int argc, char **argv);
#endif
int set_sta_static(int argc, char **argv);
int set_ap(int argc, char **argv);
int set_ap_mac(int argc, char **argv);
int set_ap_ip(int argc, char **argv);

// AP disable flag (persisted in NVS as "ap_disabled")
extern bool ap_disabled;

// AP NAT mode (1 = NAT enabled (default), 0 = routed/no NAT; persisted in NVS as "ap_nat")
extern uint8_t ap_nat_enabled;

// Dynamically enable or disable the AP interface (persists to NVS)
void ap_set_enabled(bool enabled);

esp_err_t get_config_param_blob(char* name, uint8_t** blob, size_t blob_len);
esp_err_t get_config_param_int(char* name, int* param);
esp_err_t get_config_param_str(char* name, char** param);

esp_err_t set_config_param_str(const char* name, const char* value);
esp_err_t set_config_param_int(const char* name, int32_t value);
esp_err_t set_config_param_blob(const char* name, const void* data, size_t len);

#ifdef __cplusplus
}
#endif
