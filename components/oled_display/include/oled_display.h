#pragma once

#include "esp_err.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OLED_DEFAULT_SDA  5
#define OLED_DEFAULT_SCL  6
#define OLED_I2C_ADDR     0x3C

/**
 * @brief Initialize OLED display from NVS config.
 * If enabled, starts the display update task.
 */
void oled_display_init(void);

/**
 * @brief Enable OLED display (persisted to NVS, requires reboot).
 */
void oled_display_enable(void);

/**
 * @brief Disable OLED display (persisted to NVS, requires reboot).
 */
void oled_display_disable(void);

/**
 * @brief Set I2C GPIO pins (persisted to NVS, requires reboot).
 */
void oled_display_set_gpio(int sda, int scl);

/**
 * @brief Get current OLED config.
 * @param[out] enabled  Whether OLED is enabled
 * @param[out] sda      SDA GPIO pin
 * @param[out] scl      SCL GPIO pin
 */
void oled_display_get_config(bool *enabled, int *sda, int *scl);

#ifdef __cplusplus
}
#endif
