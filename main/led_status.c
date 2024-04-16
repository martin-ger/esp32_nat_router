#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/gpio.h"
#include "router_globals.h"

#ifdef CONFIG_IDF_TARGET_ESP32C6
#include "led_strip.h"
#define BLINK_GPIO 8

static led_strip_handle_t led_strip;

static void blink_led(int led_state)
{
    if (led_state) {
        /* Set the LED pixel using RGB from 0 (0%) to 255 (100%) for each color */
        led_strip_set_pixel(led_strip, 0, 16, 16, 16);
        led_strip_refresh(led_strip);
    } else {
        led_strip_clear(led_strip);
    }
}

static void configure_led(void)
{
    led_strip_config_t strip_config = {
        .strip_gpio_num = BLINK_GPIO,
        .max_leds = 1,
    };
    led_strip_rmt_config_t rmt_config = {
        .resolution_hz = 10 * 1000 * 1000,
        .flags.with_dma = false,
    };
    ESP_ERROR_CHECK(led_strip_new_rmt_device(&strip_config, &rmt_config, &led_strip));
    led_strip_clear(led_strip);
}

#else
// On board LED
#ifdef CONFIG_IDF_TARGET_ESP32S3
#define BLINK_GPIO 44
#else
#define BLINK_GPIO 2
#endif

static void blink_led(int led_state)
{
    gpio_set_level(BLINK_GPIO, led_state);
}

static void configure_led(void)
{
    gpio_reset_pin(BLINK_GPIO);
    gpio_set_direction(BLINK_GPIO, GPIO_MODE_OUTPUT);
}

#endif

void * led_status_thread(void * p)
{
    configure_led();

    while (true)
    {
        blink_led(ap_connect);

        for (int i = 0; i < connect_count; i++)
        {
            blink_led(1 - ap_connect);
            vTaskDelay(50 / portTICK_PERIOD_MS);
            blink_led(ap_connect);
            vTaskDelay(50 / portTICK_PERIOD_MS);
        }

        vTaskDelay(1000 / portTICK_PERIOD_MS);
    }
}
