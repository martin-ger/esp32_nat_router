/* OLED Display driver for SSD1306 over I2C
 *
 * ESP32-C3 build: 72x40 SSD1306 (0.42") on GPIO 5/6, disabled by default.
 * ESP32-S3 build: 128x64 SSD1306 on GPIO 17/18, disabled by default.
 */

#include "oled_display.h"

#if defined(CONFIG_IDF_TARGET_ESP32C3) || defined(CONFIG_IDF_TARGET_ESP32S3)

#include <string.h>
#include <stdio.h>
#include "oled_display.h"
#include "font5x7.h"
#include "esp_log.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "driver/i2c_master.h"
#include "driver/gpio.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_netif_ip_addr.h"
#include "esp_wifi.h"
#include "lwip/ip4_addr.h"

/* Extern router globals (avoid including router_globals.h to prevent circular deps) */
extern bool ap_connect;
extern uint16_t connect_count;
extern uint32_t my_ip;
extern uint32_t my_ap_ip;
extern char *ssid;
extern char *ap_ssid;
extern uint64_t sta_bytes_sent;
extern uint64_t sta_bytes_received;
extern void resync_connect_count(void);
extern bool vpn_is_connected(void);

static const char *TAG = "oled";

#define PARAM_NAMESPACE "esp32_nat"

#if defined(CONFIG_IDF_TARGET_ESP32S3)
/* SSD1306 128x64 display parameters (Heltec WiFi LoRa 32 V3) */
#define OLED_WIDTH        128
#define OLED_HEIGHT       64
#define OLED_PAGES        8
#define OLED_COL_OFFSET   0
/* Heltec WiFi LoRa 32 V3 control pins */
#define HELTEC_VEXT_GPIO      GPIO_NUM_36
#define HELTEC_OLED_RST_GPIO  GPIO_NUM_21
#else
/* SSD1306 72x40 display parameters */
#define OLED_WIDTH        72
#define OLED_HEIGHT       40
#define OLED_PAGES        5
#define OLED_COL_OFFSET   28
#endif
#define FB_SIZE           (OLED_WIDTH * OLED_PAGES)
/* define display pages */
#define OLED_PAGE_COUNT     2
#define OLED_PAGE_INTERVAL  5000  /* ms per page */
/* Character dimensions */
#define CHAR_W  6  /* 5 pixel glyph + 1 pixel spacing */
#define MAX_COLS (OLED_WIDTH / CHAR_W)

/* Set larger font for ESP32S3 */
#if defined(CONFIG_IDF_TARGET_ESP32S3)
#define BIG_CHAR_W   11   /* 10 px glyph + 1 px spacing */
#define BIG_CHAR_H   16   /* 14 px glyph + 2 px spacing */
#define BIG_MAX_COLS (OLED_WIDTH / BIG_CHAR_W)
#define BIG_MAX_ROWS (OLED_HEIGHT / BIG_CHAR_H)
#endif

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

static void fb_set_pixel(int x, int y)
{
    if (x < 0 || x >= OLED_WIDTH || y < 0 || y >= OLED_HEIGHT)
        return;

    int page = y / 8;
    int bit  = y % 8;
    framebuffer[page * OLED_WIDTH + x] |= (1 << bit);
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

#if defined(CONFIG_IDF_TARGET_ESP32S3)
static void fb_draw_char_2x(int x, int y, char c)
{
    if (c < 0x20 || c > 0x7E)
        c = '?';

    const uint8_t *glyph = &font5x7[(c - 0x20) * 5];

    for (int gx = 0; gx < 5; gx++) {
        uint8_t col_bits = glyph[gx];

        for (int gy = 0; gy < 7; gy++) {
            if (col_bits & (1 << gy)) {
                int px = x + gx * 2;
                int py = y + gy * 2;

                fb_set_pixel(px,     py);
                fb_set_pixel(px + 1, py);
                fb_set_pixel(px,     py + 1);
                fb_set_pixel(px + 1, py + 1);
            }
        }
    }
}

static void fb_draw_string_2x(int row, const char *str)
{
    int x = 0;
    int y = row * BIG_CHAR_H;

    for (int i = 0; str[i] && i < BIG_MAX_COLS; i++) {
        fb_draw_char_2x(x, y, str[i]);
        x += BIG_CHAR_W;
    }
}
#endif

/* ---- I2C / SSD1306 low-level ---- */

static esp_err_t oled_cmd(uint8_t cmd)
{
    uint8_t buf[2] = { 0x00, cmd };  /* Co=0, D/C#=0 */
    return i2c_master_transmit(i2c_dev, buf, sizeof(buf), 100);
}

static esp_err_t oled_init_display(void)
{
#if defined(CONFIG_IDF_TARGET_ESP32S3)
    /* SSD1306 init sequence for 128x64 */
    static const uint8_t init_cmds[] = {
        0xAE,       /* Display off */
        0xD5, 0x80, /* Clock divide ratio */
        0xA8, 0x3F, /* Multiplex ratio = 63 (64 rows) */
        0xD3, 0x00, /* Display offset = 0 */
        0x40,       /* Start line = 0 */
        0x8D, 0x14, /* Charge pump enable */
        0x20, 0x00, /* Horizontal addressing mode */
        0xA1,       /* Segment remap */
        0xC8,       /* COM scan descending */
        0xDA, 0x12, /* COM pins config for 128x64 */
        0x81, 0xCF, /* Contrast */
        0xD9, 0xF1, /* Pre-charge period */
        0xDB, 0x40, /* VCOMH deselect level */
        0xA4,       /* Display from RAM */
        0xA6,       /* Normal display */
        0xAF,       /* Display on */
    };
#else
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
#endif

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

/* format pages */
static void format_ip(char *out, size_t out_sz, uint32_t ip)
{
    if (ip == 0) {
        snprintf(out, out_sz, "No IP");
        return;
    }

    ip4_addr_t addr;
    addr.addr = ip;
    snprintf(out, out_sz, IPSTR, IP2STR(&addr));
}

/* ---- Status rendering ---- */

static void render_status(int page)
{
    char line[24];
    char ipbuf[20];

    fb_clear();

#if defined(CONFIG_IDF_TARGET_ESP32S3)

    if (page == 0) {
        /* Page 1: SSIDs with big labels and normal values */
        fb_draw_string_2x(0, "AP");
        fb_draw_string(2, (ap_ssid != NULL && ap_ssid[0] != '\0') ? ap_ssid : "NO AP");

        fb_draw_string_2x(2, "UP");
        fb_draw_string(6, (ssid != NULL && ssid[0] != '\0') ? ssid : "NO UPLINK");

        fb_draw_string(7, "Page 1/2");
    } else {
        /* Page 2: IPs with big labels and normal values */
        fb_draw_string_2x(0, "AP IP");
        format_ip(ipbuf, sizeof(ipbuf), my_ap_ip);
        fb_draw_string(2, ipbuf);

        fb_draw_string_2x(2, "STA IP");
        if (ap_connect) {
            format_ip(ipbuf, sizeof(ipbuf), my_ip);
            fb_draw_string(6, ipbuf);

            wifi_ap_record_t ap_info;
            if (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK) {
                snprintf(line, sizeof(line), "%ddB C:%u  2/2", ap_info.rssi, (unsigned)connect_count);
            } else {
                snprintf(line, sizeof(line), "UP C:%u  2/2", (unsigned)connect_count);
            }
        } else {
            fb_draw_string(6, "DOWN");
            snprintf(line, sizeof(line), "C:%u  2/2", (unsigned)connect_count);
        }

        fb_draw_string(7, line);
    }

#else
    /* Keep the original compact layout on C3 */
    fb_draw_string(0, ap_ssid != NULL ? ap_ssid : "NO AP");

    if (ap_connect) {
        const char *status = vpn_is_connected() ? "VPN" : "UP";
        wifi_ap_record_t ap_info;
        if (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK) {
            snprintf(line, sizeof(line), "%s %ddBm", status, ap_info.rssi);
        } else {
            snprintf(line, sizeof(line), "%s", status);
        }
        fb_draw_string(1, line);
    } else {
        fb_draw_string(1, "DOWN");
    }

    if (ap_connect && my_ip != 0) {
        ip4_addr_t addr;
        addr.addr = my_ip;
        snprintf(line, sizeof(line), IPSTR, IP2STR(&addr));
        int len = strlen(line);
        fb_draw_string(2, len > MAX_COLS ? line + (len - MAX_COLS) : line);
    } else {
        fb_draw_string(2, "No IP");
    }

    snprintf(line, sizeof(line), "Clients: %d", connect_count);
    fb_draw_string(3, line);

    snprintf(line, sizeof(line), "%.1f/%.1f MB",
             sta_bytes_sent / (1024.0 * 1024.0),
             sta_bytes_received / (1024.0 * 1024.0));
    fb_draw_string(4, line);
#endif
}

/* ---- FreeRTOS task ---- */

#if defined(CONFIG_IDF_TARGET_ESP32S3)
static void heltec_oled_power_and_reset(void)
{
    /* Turn on Vext: LOW = ON */
    gpio_reset_pin(HELTEC_VEXT_GPIO);
    gpio_set_direction(HELTEC_VEXT_GPIO, GPIO_MODE_OUTPUT);
    gpio_set_level(HELTEC_VEXT_GPIO, 0);
    vTaskDelay(pdMS_TO_TICKS(50));

    /* Reset OLED */
    gpio_reset_pin(HELTEC_OLED_RST_GPIO);
    gpio_set_direction(HELTEC_OLED_RST_GPIO, GPIO_MODE_OUTPUT);

    gpio_set_level(HELTEC_OLED_RST_GPIO, 1);
    vTaskDelay(pdMS_TO_TICKS(5));
    gpio_set_level(HELTEC_OLED_RST_GPIO, 0);
    vTaskDelay(pdMS_TO_TICKS(20));
    gpio_set_level(HELTEC_OLED_RST_GPIO, 1);
    vTaskDelay(pdMS_TO_TICKS(50));
}
#endif

static void oled_task(void *arg)
{
    int sda = ((int *)arg)[0];
    int scl = ((int *)arg)[1];

#if defined(CONFIG_IDF_TARGET_ESP32S3)
    heltec_oled_power_and_reset();
#endif

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

    ESP_LOGI(TAG, "OLED %dx%d running on SDA=%d SCL=%d", OLED_WIDTH, OLED_HEIGHT, sda, scl);

    int resync_counter = 0;
    int current_page = 0;

    while (true) {
        if (++resync_counter >= 30) {
            resync_connect_count();
            resync_counter = 0;
        }

        render_status(current_page);

        err = oled_flush();
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "OLED write failed: %s - stopping", esp_err_to_name(err));
            break;
        }

        current_page = (current_page + 1) % OLED_PAGE_COUNT;
        vTaskDelay(pdMS_TO_TICKS(OLED_PAGE_INTERVAL));
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
#if defined(CONFIG_IDF_TARGET_ESP32S3)
    bool enabled = false;
#else
    bool enabled = false;
#endif
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

    #if defined(CONFIG_IDF_TARGET_ESP32S3)
    *enabled = true;
#else
    *enabled = false;
#endif
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

#endif /* CONFIG_IDF_TARGET_ESP32C3 || CONFIG_IDF_TARGET_ESP32S3 */
