/* OLED Display driver for SSD1306 72x40 (0.42") over I2C
 *
 * Shows router status: AP SSID, STA connection, IPs, client count.
 * Disabled by default, configured via CLI with NVS persistence.
 */

#include <string.h>
#include <stdio.h>
#include "oled_display.h"
#include "font5x7.h"
#include "esp_log.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "driver/i2c_master.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_netif_ip_addr.h"
#include "esp_wifi.h"
#include "lwip/ip4_addr.h"

/* Extern router globals (avoid including router_globals.h to prevent circular deps) */
extern bool ap_connect;
extern uint16_t connect_count;
extern uint32_t my_ip;
extern char *ap_ssid;
extern uint64_t sta_bytes_sent;
extern uint64_t sta_bytes_received;

static const char *TAG = "oled";

#define PARAM_NAMESPACE "esp32_nat"

/* SSD1306 72x40 display parameters */
#define OLED_WIDTH        72
#define OLED_HEIGHT       40
#define OLED_PAGES        5   /* 40 / 8 = 5 */
#define OLED_COL_OFFSET   28  /* 72x40 panels start at column 28 */
#define FB_SIZE           (OLED_WIDTH * OLED_PAGES)  /* 360 bytes */

/* Character dimensions */
#define CHAR_W  6  /* 5 pixel glyph + 1 pixel spacing */
#define CHAR_H  8  /* one page */
#define MAX_COLS (OLED_WIDTH / CHAR_W)  /* 12 chars per line */

/* Static framebuffer */
static uint8_t framebuffer[FB_SIZE];

/* I2C handle */
static i2c_master_bus_handle_t i2c_bus = NULL;
static i2c_master_dev_handle_t i2c_dev = NULL;

/* ---- Framebuffer operations ---- */

static void fb_clear(void)
{
    memset(framebuffer, 0, FB_SIZE);
}

static void fb_draw_char(int col, int page, char c)
{
    if (col < 0 || col >= OLED_WIDTH - 4 || page < 0 || page >= OLED_PAGES)
        return;
    if (c < 0x20 || c > 0x7E)
        c = '?';
    const uint8_t *glyph = &font5x7[(c - 0x20) * 5];
    for (int i = 0; i < 5; i++) {
        framebuffer[page * OLED_WIDTH + col + i] = glyph[i];
    }
}

static void fb_draw_string(int page, const char *str)
{
    int col = 0;
    for (int i = 0; str[i] && i < MAX_COLS; i++) {
        fb_draw_char(col, page, str[i]);
        col += CHAR_W;
    }
}

/* ---- I2C / SSD1306 low-level ---- */

static esp_err_t oled_cmd(uint8_t cmd)
{
    uint8_t buf[2] = { 0x00, cmd };  /* Co=0, D/C#=0 */
    return i2c_master_transmit(i2c_dev, buf, sizeof(buf), 100);
}

static esp_err_t oled_init_display(void)
{
    /* SSD1306 init sequence for 72x40 */
    static const uint8_t init_cmds[] = {
        0xAE,       /* Display off */
        0xD5, 0x80, /* Clock divide ratio */
        0xA8, 0x27, /* Multiplex ratio = 39 (40 rows) */
        0xD3, 0x00, /* Display offset = 0 */
        0x40,       /* Start line = 0 */
        0x8D, 0x14, /* Charge pump enable */
        0x20, 0x00, /* Horizontal addressing mode */
        0xA1,       /* Segment remap (flip horizontal) */
        0xC8,       /* COM scan descending (flip vertical) */
        0xDA, 0x12, /* COM pins config */
        0x81, 0xCF, /* Contrast */
        0xD9, 0xF1, /* Pre-charge period */
        0xDB, 0x40, /* VCOMH deselect level */
        0xA4,       /* Display from RAM */
        0xA6,       /* Normal display (not inverted) */
        0xAF,       /* Display on */
    };

    for (size_t i = 0; i < sizeof(init_cmds); i++) {
        esp_err_t err = oled_cmd(init_cmds[i]);
        if (err != ESP_OK) return err;
    }
    return ESP_OK;
}

static esp_err_t oled_flush(void)
{
    /* Set column address range */
    esp_err_t err;
    err = oled_cmd(0x21);  if (err != ESP_OK) return err;
    err = oled_cmd(OLED_COL_OFFSET);  if (err != ESP_OK) return err;
    err = oled_cmd(OLED_COL_OFFSET + OLED_WIDTH - 1);  if (err != ESP_OK) return err;

    /* Set page address range */
    err = oled_cmd(0x22);  if (err != ESP_OK) return err;
    err = oled_cmd(0);     if (err != ESP_OK) return err;
    err = oled_cmd(OLED_PAGES - 1);  if (err != ESP_OK) return err;

    /* Send framebuffer data (prefix with 0x40 = data) */
    static uint8_t tx_buf[1 + FB_SIZE];
    tx_buf[0] = 0x40;
    memcpy(&tx_buf[1], framebuffer, FB_SIZE);
    return i2c_master_transmit(i2c_dev, tx_buf, sizeof(tx_buf), 200);
}

/* ---- Status rendering ---- */

static void render_status(void)
{
    char line[20];  /* sized for IP and status formatting, truncated by fb_draw_string */

    fb_clear();

    /* Line 0: AP SSID (truncated by fb_draw_string) */
    fb_draw_string(0, ap_ssid != NULL ? ap_ssid : "NO AP");

    /* Line 1: STA status with RSSI */
    if (ap_connect) {
        wifi_ap_record_t ap_info;
        if (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK) {
            snprintf(line, sizeof(line), "UP %d dB", ap_info.rssi);
        } else {
            snprintf(line, sizeof(line), "UP");
        }
        fb_draw_string(1, line);
    } else {
        fb_draw_string(1, "DOWN");
    }

    /* Line 2: STA IP (truncated from front if too long for display) */
    if (ap_connect && my_ip != 0) {
        ip4_addr_t addr;
        addr.addr = my_ip;
        snprintf(line, sizeof(line), IPSTR, IP2STR(&addr));
        int len = strlen(line);
        fb_draw_string(2, len > MAX_COLS ? line + (len - MAX_COLS) : line);
    } else {
        fb_draw_string(2, "No IP");
    }

    /* Line 3: Client count */
    snprintf(line, sizeof(line), "Clients: %d", connect_count);
    fb_draw_string(3, line);

    /* Line 4: Sent/Received MB */
    snprintf(line, sizeof(line), "%.1f/%.1f MB",
             sta_bytes_sent / (1024.0 * 1024.0),
             sta_bytes_received / (1024.0 * 1024.0));
    fb_draw_string(4, line);
}

/* ---- FreeRTOS task ---- */

static void oled_task(void *arg)
{
    int sda = ((int *)arg)[0];
    int scl = ((int *)arg)[1];

    /* Configure I2C master bus */
    i2c_master_bus_config_t bus_cfg = {
        .i2c_port = -1,  /* auto-select */
        .sda_io_num = sda,
        .scl_io_num = scl,
        .clk_source = I2C_CLK_SRC_DEFAULT,
        .glitch_ignore_cnt = 7,
        .flags.enable_internal_pullup = true,
    };
    esp_err_t err = i2c_new_master_bus(&bus_cfg, &i2c_bus);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "I2C bus init failed: %s", esp_err_to_name(err));
        vTaskDelete(NULL);
        return;
    }

    i2c_device_config_t dev_cfg = {
        .dev_addr_length = I2C_ADDR_BIT_LEN_7,
        .device_address = OLED_I2C_ADDR,
        .scl_speed_hz = 400000,
    };
    err = i2c_master_bus_add_device(i2c_bus, &dev_cfg, &i2c_dev);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "I2C device add failed: %s", esp_err_to_name(err));
        i2c_del_master_bus(i2c_bus);
        i2c_bus = NULL;
        vTaskDelete(NULL);
        return;
    }

    err = oled_init_display();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "OLED init failed: %s (check wiring SDA=%d SCL=%d)", esp_err_to_name(err), sda, scl);
        i2c_master_bus_rm_device(i2c_dev);
        i2c_del_master_bus(i2c_bus);
        i2c_dev = NULL;
        i2c_bus = NULL;
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "OLED 72x40 running on SDA=%d SCL=%d", sda, scl);

    while (true) {
        render_status();
        err = oled_flush();
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "OLED write failed: %s - stopping", esp_err_to_name(err));
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(2000));
    }

    /* Cleanup on failure */
    if (i2c_dev) {
        i2c_master_bus_rm_device(i2c_dev);
        i2c_dev = NULL;
    }
    if (i2c_bus) {
        i2c_del_master_bus(i2c_bus);
        i2c_bus = NULL;
    }
    vTaskDelete(NULL);
}

/* ---- Public API ---- */

/* Static storage for GPIO pins (passed to task) */
static int gpio_pins[2];

void oled_display_init(void)
{
    bool enabled = false;
    int sda = OLED_DEFAULT_SDA;
    int scl = OLED_DEFAULT_SCL;

    oled_display_get_config(&enabled, &sda, &scl);

    if (!enabled) {
        ESP_LOGI(TAG, "OLED display disabled");
        return;
    }

    gpio_pins[0] = sda;
    gpio_pins[1] = scl;

    xTaskCreate(oled_task, "oled", 3072, gpio_pins, 2, NULL);
}

void oled_display_enable(void)
{
    nvs_handle_t nvs;
    if (nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs) == ESP_OK) {
        nvs_set_i32(nvs, "oled_en", 1);
        nvs_commit(nvs);
        nvs_close(nvs);
    }
}

void oled_display_disable(void)
{
    nvs_handle_t nvs;
    if (nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs) == ESP_OK) {
        nvs_set_i32(nvs, "oled_en", 0);
        nvs_commit(nvs);
        nvs_close(nvs);
    }
}

void oled_display_set_gpio(int sda, int scl)
{
    nvs_handle_t nvs;
    if (nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs) == ESP_OK) {
        nvs_set_i32(nvs, "oled_sda", sda);
        nvs_set_i32(nvs, "oled_scl", scl);
        nvs_commit(nvs);
        nvs_close(nvs);
    }
}

void oled_display_get_config(bool *enabled, int *sda, int *scl)
{
    nvs_handle_t nvs;
    int32_t val;

    *enabled = false;
    *sda = OLED_DEFAULT_SDA;
    *scl = OLED_DEFAULT_SCL;

    if (nvs_open(PARAM_NAMESPACE, NVS_READONLY, &nvs) != ESP_OK)
        return;

    if (nvs_get_i32(nvs, "oled_en", &val) == ESP_OK)
        *enabled = (val != 0);
    if (nvs_get_i32(nvs, "oled_sda", &val) == ESP_OK)
        *sda = (int)val;
    if (nvs_get_i32(nvs, "oled_scl", &val) == ESP_OK)
        *scl = (int)val;

    nvs_close(nvs);
}
