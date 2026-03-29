/* Addressable LED strip status indicator — implementation.
 *
 * ESP32-C5: GPIO bit-bang driver (no RMT dependency, saves ~10 KB flash).
 * All other targets: espressif/led_strip managed component (RMT backend).
 *
 * SPDX-License-Identifier: MIT
 */

#include "led_strip_status.h"
#include "router_config.h"
#include "wifi_config.h"
#include "esp_log.h"

static const char *TAG = "led_strip";

/* ---- Global ---- */
int led_strip_gpio = -1;

/* ---- Private state (common) ---- */
static volatile bool traffic_flag = false;
static volatile bool factory_reset_flag = false;

/* ======================================================================
 * ESP32-C5: bit-bang WS2812 via direct GPIO register writes
 * ====================================================================== */
#if CONFIG_IDF_TARGET_ESP32C5

#include "driver/gpio.h"
#include "soc/gpio_reg.h"
#include "esp_cpu.h"
#include "esp_rom_sys.h"
#include "freertos/FreeRTOS.h"

/* Timing assumes 240 MHz CPU. Catch misconfiguration at compile time. */
_Static_assert(CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ == 240,
    "ws2812 bit-bang timing constants assume 240 MHz CPU — update WS2812_* macros");

#define WS2812_T0H_CYCLES    96   /* 400 ns @ 240 MHz */
#define WS2812_T1H_CYCLES   204   /* 850 ns @ 240 MHz */
#define WS2812_PERIOD_CYCLES 300  /* 1250 ns @ 240 MHz */
#define WS2812_RESET_US       55  /* >50 µs reset pulse */

static bool strip_inited = false;
static uint32_t ws2812_pin_mask;  /* precomputed (1 << gpio), set in init */

static IRAM_ATTR void ws2812_write_byte(uint8_t byte)
{
    for (int i = 7; i >= 0; i--) {
        uint32_t t0 = esp_cpu_get_cycle_count();
        REG_WRITE(GPIO_OUT_W1TS_REG, ws2812_pin_mask);   /* HIGH */
        uint32_t th = (byte >> i & 1) ? WS2812_T1H_CYCLES : WS2812_T0H_CYCLES;
        while ((uint32_t)(esp_cpu_get_cycle_count() - t0) < th);
        REG_WRITE(GPIO_OUT_W1TC_REG, ws2812_pin_mask);   /* LOW */
        while ((uint32_t)(esp_cpu_get_cycle_count() - t0) < WS2812_PERIOD_CYCLES);
    }
}

static void ws2812_send(uint8_t r, uint8_t g, uint8_t b)
{
    portDISABLE_INTERRUPTS();
    ws2812_write_byte(g);   /* WS2812 order: G R B */
    ws2812_write_byte(r);
    ws2812_write_byte(b);
    portENABLE_INTERRUPTS();
    esp_rom_delay_us(WS2812_RESET_US);
}

void led_strip_status_init(void)
{
    if (led_strip_gpio < 0) {
        ESP_LOGI(TAG, "LED strip disabled (no GPIO configured)");
        return;
    }
    ws2812_pin_mask = (1UL << led_strip_gpio);
    gpio_config_t io = {
        .pin_bit_mask = ws2812_pin_mask,
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    gpio_config(&io);
    REG_WRITE(GPIO_OUT_W1TC_REG, ws2812_pin_mask);  /* idle LOW */
    strip_inited = true;
    ESP_LOGI(TAG, "LED strip (bit-bang) on GPIO %d", led_strip_gpio);
}

bool led_strip_is_active(void)
{
    return strip_inited;
}

void led_strip_status_update(void)
{
    if (!strip_inited)
        return;

    static uint8_t tick = 0;
    tick++;

    if (factory_reset_flag) {
        ws2812_send(tick & 1 ? 60 : 0, 0, tick & 1 ? 0 : 60);
        return;
    }

    if (traffic_flag) {
        traffic_flag = false;
        if (ap_connect) {
            ws2812_send(40, 60, 60);
            return;
        }
    }

    if (!ap_connect) {
        uint8_t phase = tick % 40;
        uint8_t brightness = (phase < 20) ? (5 + phase * 2) : (5 + (40 - phase) * 2);
        ws2812_send(brightness, 0, 0);
        return;
    }

    uint8_t base = 8;
    uint8_t extra = connect_count * 6;
    if (extra > 52) extra = 52;
    ws2812_send(0, base + extra, 0);
}

/* ======================================================================
 * All other targets: espressif/led_strip managed component (RMT backend)
 * ====================================================================== */
#else

#include "led_strip.h"

static led_strip_handle_t strip_handle = NULL;

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
        .resolution_hz = 10 * 1000 * 1000,
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

bool led_strip_is_active(void)
{
    return strip_handle != NULL;
}

void led_strip_status_update(void)
{
    if (strip_handle == NULL)
        return;

    static uint8_t tick = 0;
    tick++;

    if (factory_reset_flag) {
        if (tick & 1)
            strip_set_rgb(60, 0, 0);
        else
            strip_set_rgb(0, 0, 60);
        return;
    }

    if (traffic_flag) {
        traffic_flag = false;
        if (ap_connect) {
            strip_set_rgb(40, 60, 60);
            return;
        }
    }

    if (!ap_connect) {
        uint8_t phase = tick % 40;
        uint8_t brightness = (phase < 20) ? (5 + phase * 2) : (5 + (40 - phase) * 2);
        strip_set_rgb(brightness, 0, 0);
        return;
    }

    uint8_t base = 8;
    uint8_t extra = connect_count * 6;
    if (extra > 52) extra = 52;
    strip_set_rgb(0, base + extra, 0);
}

#endif /* CONFIG_IDF_TARGET_ESP32C5 */

/* ---- Public API (common to both implementations) ---- */

void led_strip_notify_traffic(void)
{
    traffic_flag = true;
}

void led_strip_set_factory_reset(bool active)
{
    factory_reset_flag = active;
}
