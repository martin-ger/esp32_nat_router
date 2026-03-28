/* WireGuard VPN management.
 *
 * Handles VPN connection/disconnection, SNTP time sync (required for
 * WireGuard timestamps), and VPN subnet helpers for the kill switch.
 */

#include <string.h>
#include <time.h>
#include "esp_log.h"
#include "esp_wireguard.h"
#include "esp_sntp.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/ip_addr.h"
#include "vpn_config.h"
#include "router_config.h"
#include "portmap.h"

static const char *TAG = "vpn_mgr";

// Cached VPN subnet for kill switch (network byte order)
static uint32_t vpn_subnet_ip = 0;
static uint32_t vpn_subnet_mask = 0;

// WireGuard context (module-private)
static wireguard_config_t wg_config = ESP_WIREGUARD_CONFIG_DEFAULT();
static wireguard_ctx_t wg_ctx = {0};
static bool wg_initialized = false;

void vpn_set_subnet(uint32_t ip, uint32_t mask) {
    vpn_subnet_ip = ip;
    vpn_subnet_mask = mask;
}

IRAM_ATTR bool vpn_in_subnet(uint32_t ip) {
    if (vpn_subnet_mask == 0) return false;
    return (ip & vpn_subnet_mask) == vpn_subnet_ip;
}

esp_err_t vpn_connect(void)
{
    if (!vpn_enabled) {
        ESP_LOGI(TAG, "VPN not enabled");
        return ESP_ERR_INVALID_STATE;
    }
    if (vpn_private_key == NULL || strlen(vpn_private_key) == 0 ||
        vpn_public_key == NULL || strlen(vpn_public_key) == 0 ||
        vpn_endpoint == NULL || strlen(vpn_endpoint) == 0 ||
        vpn_address == NULL || strlen(vpn_address) == 0) {
        ESP_LOGE(TAG, "VPN missing required config (privkey, pubkey, endpoint, address)");
        return ESP_ERR_INVALID_ARG;
    }

    wg_config.private_key = vpn_private_key;
    wg_config.public_key = vpn_public_key;
    wg_config.preshared_key = (vpn_preshared_key && strlen(vpn_preshared_key) > 0) ? vpn_preshared_key : NULL;
    wg_config.allowed_ip = vpn_address;
    wg_config.allowed_ip_mask = (vpn_netmask && strlen(vpn_netmask) > 0) ? vpn_netmask : "255.255.255.0";
    wg_config.endpoint = vpn_endpoint;
    wg_config.port = vpn_port;
    wg_config.persistent_keepalive = vpn_keepalive;
#if CONFIG_ETH_UPLINK
    wg_config.netif_key = "ETH_DEF";
#endif

    esp_err_t err;
    if (!wg_initialized) {
        err = esp_wireguard_init(&wg_config, &wg_ctx);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "WireGuard init failed: %s", esp_err_to_name(err));
            return err;
        }
        wg_initialized = true;
    }

    err = esp_wireguard_connect(&wg_ctx);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "WireGuard connect failed: %s", esp_err_to_name(err));
        // Reset so next attempt does a clean init (avoids leaked netif/timers)
        wg_initialized = false;
        memset(&wg_ctx, 0, sizeof(wg_ctx));
        return err;
    }

    if (vpn_route_all) {
        err = esp_wireguard_set_default(&wg_ctx);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "WireGuard set_default failed: %s", esp_err_to_name(err));
        }
    }

    ap_mss_clamp = 1380;
    ap_pmtu = 1440;
    vpn_connected = true;

    /* Cache VPN tunnel IP and activate VPN-bound port mappings */
    if (wg_ctx.netif) {
        vpn_tunnel_ip = ip_2_ip4(&wg_ctx.netif->ip_addr)->addr;
    }
    delete_portmap_tab();
    apply_portmap_tab();

    ESP_LOGI(TAG, "WireGuard VPN connected%s, MSS=1380 PMTU=1440",
             vpn_route_all ? "" : " (split tunnel)");
    return ESP_OK;
}

void vpn_disconnect(void)
{
    // Set vpn_connected false FIRST to prevent race with vpn_is_connected()
    // (called from netif hooks and HTTP handlers in other tasks)
    vpn_connected = false;
    vpn_tunnel_ip = 0;
    ap_mss_clamp = 0;
    ap_pmtu = 0;

    /* Deactivate VPN portmaps, keep STA ones */
    delete_portmap_tab();
    apply_portmap_tab();

    if (wg_initialized) {
        esp_wireguard_disconnect(&wg_ctx);
        wg_initialized = false;
    }
    ESP_LOGI(TAG, "WireGuard VPN disconnected, MSS/PMTU disabled");
}

IRAM_ATTR bool vpn_is_connected(void)
{
    if (!wg_initialized || !vpn_connected || !wg_ctx.netif) {
        return false;
    }
    return esp_wireguardif_peer_is_up(&wg_ctx) == ESP_OK;
}

static void init_sntp(void)
{
    ESP_LOGI(TAG, "Initializing SNTP");
    esp_sntp_setoperatingmode(ESP_SNTP_OPMODE_POLL);
    esp_sntp_setservername(0, "pool.ntp.org");
    esp_sntp_setservername(1, "time.nist.gov");
    esp_sntp_setservername(2, "time.google.com");
    esp_sntp_init();
}

void vpn_connect_task(void *pvParameters)
{
    // Wait for SNTP time sync before connecting VPN
    // WireGuard uses TAI64N timestamps - needs valid wall clock after reboot
    int retry = 0;
    const int max_retry = 60;  // 30 seconds max
    time_t now = 0;
    while (retry < max_retry) {
        time(&now);
        // Consider time valid if after 2020-01-01
        if (now > 1577836800) {
            break;
        }
        if (retry % 4 == 0) {
            ESP_LOGI(TAG, "Waiting for SNTP time sync... (%d/%ds)", retry / 2, max_retry / 2);
        }
        vTaskDelay(pdMS_TO_TICKS(500));
        retry++;
    }
    if (now > 1577836800) {
        struct tm timeinfo;
        localtime_r(&now, &timeinfo);
        ESP_LOGI(TAG, "Time synchronized: %04d-%02d-%02d %02d:%02d:%02d",
                 timeinfo.tm_year + 1900, timeinfo.tm_mon + 1, timeinfo.tm_mday,
                 timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);
    } else {
        ESP_LOGW(TAG, "SNTP sync timeout after %ds, proceeding with VPN anyway", max_retry / 2);
    }
    vpn_connect();
    vTaskDelete(NULL);
}

void init_sntp_if_needed(void)
{
    if (!esp_sntp_enabled()) {
        init_sntp();
    }
}
