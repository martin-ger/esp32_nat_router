/* MQTT Home Assistant auto-discovery integration.
 *
 * SPDX-License-Identifier: MIT
 */
#pragma once

#include "esp_err.h"

#ifdef CONFIG_MQTT_HOMEASSISTANT

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize MQTT HA module: load NVS config, register CLI, start if enabled.
 *        Call once from app_main() after WiFi and console init.
 */
void mqtt_ha_init(void);

/**
 * @brief Start MQTT client and begin publishing.
 * @return ESP_OK on success
 */
esp_err_t mqtt_ha_start(void);

/**
 * @brief Stop MQTT client and disconnect.
 * @return ESP_OK on success
 */
esp_err_t mqtt_ha_stop(void);

/**
 * @brief Re-publish all HA discovery configs (e.g. after DHCP reservation changes).
 */
void mqtt_ha_rediscover(void);

/**
 * @brief Get human-readable status string.
 * @return "connected", "disconnected", or "disabled"
 */
const char *mqtt_ha_get_status(void);

#ifdef __cplusplus
}
#endif

#endif /* CONFIG_MQTT_HOMEASSISTANT */
