/* GPIO Sensor Monitor - Periodic ADC1/Digital GPIO logging with history & CSV export
 *
 * Compiled out completely unless CONFIG_GPIO_MONITOR=y.
 * Allocates zero RAM when runtime master toggle ("gpio_en") is off.
 */
#pragma once

#include "sdkconfig.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_GPIO_SENSORS       4
#define GPIO_SENSOR_NAME_LEN   24
#if defined(CONFIG_IDF_TARGET_ESP32C3) || defined(CONFIG_IDF_TARGET_ESP32C5)
#define GPIO_HISTORY_MAX       96   /* ~1.1 KB/sensor on unified-SRAM targets */
#else
#define GPIO_HISTORY_MAX       192  /* ~2.3 KB/sensor (8 days at 1/hr) */
#endif
#define GPIO_MIN_INTERVAL_S    5
#define GPIO_MAX_INTERVAL_S    86400
#define GPIO_MIN_PERSIST_S     60

typedef enum {
    GPIO_SENSOR_ANALOG  = 0,
    GPIO_SENSOR_DIGITAL = 1,
} gpio_sensor_mode_t;

typedef struct {
    uint8_t  valid;
    uint8_t  enabled;
    int8_t   gpio;
    uint8_t  mode;          /* gpio_sensor_mode_t */
    uint8_t  persist;       /* 1 = save 8.3 CSV to /data (requires interval >= 60s) */
    uint8_t  reserved[3];
    uint32_t interval_sec;  /* 5..86400 */
    char     name[GPIO_SENSOR_NAME_LEN];
} gpio_sensor_config_t;

typedef struct {
    uint32_t unix_ts;   /* Wall-clock Unix timestamp (0 if SNTP not synced) */
    uint32_t uptime_s;  /* Seconds since boot */
    uint16_t raw;       /* Analog 0..4095, or Digital 0/1 */
    uint16_t mv;        /* Analog calibrated mV, or 0/3300 for digital */
} gpio_sample_t;

#ifdef CONFIG_GPIO_MONITOR

void gpio_monitor_init(void);
bool gpio_monitor_is_enabled(void);
esp_err_t gpio_monitor_set_enabled(bool enabled);

/** Add (slot < 0) or update (0 <= slot < MAX_GPIO_SENSORS) a sensor. */
esp_err_t gpio_monitor_set_sensor(int slot, int gpio, gpio_sensor_mode_t mode,
                                  uint32_t interval_sec, bool persist, const char *name,
                                  char *err_buf, size_t err_len);

esp_err_t gpio_monitor_del_sensor(int slot);
esp_err_t gpio_monitor_read_now(int slot);
esp_err_t gpio_monitor_clear_history(int slot);

bool gpio_monitor_get_sensor(int slot, gpio_sensor_config_t *out);
bool gpio_monitor_get_latest(int slot, gpio_sample_t *out);
size_t gpio_monitor_get_sample_count(int slot);
size_t gpio_monitor_copy_history_range(int slot, size_t offset, gpio_sample_t *out, size_t max_count);

esp_err_t load_gpio_config(void);
esp_err_t save_gpio_config(void);

#else /* !CONFIG_GPIO_MONITOR */

static inline void gpio_monitor_init(void) {}
static inline bool gpio_monitor_is_enabled(void) { return false; }

#endif /* CONFIG_GPIO_MONITOR */

#ifdef __cplusplus
}
#endif