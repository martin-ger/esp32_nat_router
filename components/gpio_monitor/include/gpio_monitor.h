/* GPIO Sensor Monitor - Periodic ADC1/Digital GPIO logging with history & CSV export
 *
 * Allocates zero RAM when disabled. Analog readings use ADC1 only (ADC2 conflicts
 * with Wi-Fi on ESP32). Optional flash persistence writes to /data when enabled.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_GPIO_SENSORS       4
#define GPIO_SENSOR_NAME_LEN   24
#define GPIO_HISTORY_MAX       192  /* 192 hourly samples = 8 days (~2.3 KB RAM/sensor when active) */
#define GPIO_MIN_INTERVAL_S    5
#define GPIO_MAX_INTERVAL_S    86400
#define GPIO_MIN_PERSIST_S     60   /* Prevent flash wear on sub-minute polling */

typedef enum {
    GPIO_SENSOR_ANALOG  = 0,
    GPIO_SENSOR_DIGITAL = 1,
} gpio_sensor_mode_t;

typedef struct {
    uint8_t  valid;
    uint8_t  enabled;
    int8_t   gpio;
    uint8_t  mode;          /* gpio_sensor_mode_t */
    uint8_t  persist;       /* 1 = save CSV to /data (requires interval >= 60s) */
    uint8_t  reserved[3];
    uint32_t interval_sec;  /* 5..86400 */
    char     name[GPIO_SENSOR_NAME_LEN];
} gpio_sensor_config_t;

typedef struct {
    uint32_t unix_ts;   /* Wall-clock Unix timestamp (0 if SNTP not yet synced) */
    uint32_t uptime_s;  /* Seconds since boot */
    uint16_t raw;       /* Analog 0..4095, or Digital 0/1 */
    uint16_t mv;        /* Analog calibrated mV, or 0/3300 for digital */
} gpio_sample_t;

/** Initialize subsystem from NVS; starts sampler only if master toggle is enabled. */
void gpio_monitor_init(void);

/** Master feature toggle (persisted in NVS as "gpio_en"). Frees all RAM when false. */
bool gpio_monitor_is_enabled(void);
esp_err_t gpio_monitor_set_enabled(bool enabled);

/** Add or update a sensor (slot < 0 picks first empty slot). Writes user-facing error to err_buf on failure. */
esp_err_t gpio_monitor_set_sensor(int slot, int gpio, gpio_sensor_mode_t mode,
                                  uint32_t interval_sec, bool persist, const char *name,
                                  char *err_buf, size_t err_len);

/** Delete a sensor slot and free its history buffer. */
esp_err_t gpio_monitor_del_sensor(int slot);

/** Trigger an immediate measurement for a sensor slot. */
esp_err_t gpio_monitor_read_now(int slot);

/** Clear recorded history (and CSV file if persisted) for a sensor slot. */
esp_err_t gpio_monitor_clear_history(int slot);

/** Copy sensor config (returns false if slot unused or out of range). */
bool gpio_monitor_get_sensor(int slot, gpio_sensor_config_t *out);

/** Copy latest sample (returns false if no samples recorded yet). */
bool gpio_monitor_get_latest(int slot, gpio_sample_t *out);

/** Get current total samples stored for a sensor slot. */
size_t gpio_monitor_get_sample_count(int slot);

/** Copy up to max_count samples starting at chronological offset (0 = oldest). */
size_t gpio_monitor_copy_history_range(int slot, size_t offset, gpio_sample_t *out, size_t max_count);

/** NVS persistence helpers (implemented in gpio_monitor_nvs.c). */
esp_err_t load_gpio_config(void);
esp_err_t save_gpio_config(void);

#ifdef __cplusplus
}
#endif