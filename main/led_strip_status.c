/* Addressable LED strip status indicator — implementation.
 *
 * Uses the espressif/led_strip managed component (RMT backend).
 * Drives a single WS2812-compatible LED to show router state.
 *
 * SPDX-License-Identifier: MIT
 */

#include "led_strip_status.h"
#include "led_strip.h"
#include "router_config.h"
#include "wifi_config.h"

#include "esp_log.h"
#include <string.h>

static const char *TAG = "led_strip";

/* ---- Global ---- */
int led_strip_gpio = -1;

/* ---- Private state ---- */
static led_strip_handle_t strip_handle = NULL;
static volatile bool traffic_flag = false;
static volatile bool factory_reset_flag = false;

/* ---- Helpers ---- */

static void strip_set_rgb(uint8_t r, uint8_t g, uint8_t b)
{
    if (strip_handle) {
        led_strip_set_pixel(strip_handle, 0, r, g, b);
        led_strip_refresh(strip_handle);
    }
}

static void strip_off(void)
{
    if (strip_handle) {
        led_strip_clear(strip_handle);
        led_strip_refresh(strip_handle);
    }
}

/* ---- Public API ---- */

void led_strip_status_init(void)
{
    if (led_strip_gpio < 0) {
        ESP_LOGI(TAG, "LED strip disabled (no GPIO configured)");
        return;
    }

    led_strip_config_t strip_config = {
        .strip_gpio_num = led_strip_gpio,
        .max_leds = 1,
        .led_model = LED_MODEL_WS2812,
        .color_component_format = LED_STRIP_COLOR_COMPONENT_FMT_GRB,
        .flags.invert_out = 0,
    };

    led_strip_rmt_config_t rmt_config = {
        .clk_src = RMT_CLK_SRC_DEFAULT,
        .resolution_hz = 10 * 1000 * 1000,  /* 10 MHz */
        .mem_block_symbols = 64,
        .flags.with_dma = false,
    };

    esp_err_t err = led_strip_new_rmt_device(&strip_config, &rmt_config, &strip_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to create LED strip on GPIO %d: %s",
                 led_strip_gpio, esp_err_to_name(err));
        strip_handle = NULL;
        return;
    }

    strip_off();
    ESP_LOGI(TAG, "LED strip on GPIO %d", led_strip_gpio);
}

void led_strip_notify_traffic(void)
{
    traffic_flag = true;
}

void led_strip_set_factory_reset(bool active)
{
    factory_reset_flag = active;
}

bool led_strip_is_active(void)
{
    return strip_handle != NULL;
}

/*
 * Called once per iteration from the led_status_thread (every ~50 ms tick).
 * This drives the colour state machine.
 *
 * We keep a simple tick counter; the thread calls us at POLL_INTERVAL_MS
 * cadence (50 ms) inside the 1-second loop — that's ~20 calls/sec.
 */
void led_strip_status_update(void)
{
    if (strip_handle == NULL)
        return;

    static uint8_t tick = 0;
    tick++;

    /* --- Factory reset: rapid red / blue --- */
    if (factory_reset_flag) {
        if (tick & 1)
            strip_set_rgb(60, 0, 0);
        else
            strip_set_rgb(0, 0, 60);
        return;
    }

    /* --- Traffic flash: brief white/cyan burst --- */
    if (traffic_flag) {
        traffic_flag = false;
        if (ap_connect) {
            strip_set_rgb(40, 60, 60);   /* cyan-white flash */
            return;                       /* hold for one tick (~50 ms) */
        }
    }

    /* --- Disconnected: red, slow pulse --- */
    if (!ap_connect) {
        /* Triangular pulse: brightness 5..40 over ~2 s (40 ticks) */
        uint8_t phase = tick % 40;
        uint8_t brightness = (phase < 20) ? (5 + phase * 2) : (5 + (40 - phase) * 2);
        strip_set_rgb(brightness, 0, 0);
        return;
    }

    /* --- Connected: green, brightness scales with client count --- */
    uint8_t base = 8;   /* dim when idle / no clients */
    uint8_t extra = connect_count * 6;
    if (extra > 52) extra = 52;
    strip_set_rgb(0, base + extra, 0);
}
