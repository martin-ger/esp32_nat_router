/* GPIO Sensor Monitor implementation (ESP-IDF 5.5+ oneshot ADC1 & GPIO) */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "driver/gpio.h"
#include "esp_adc/adc_oneshot.h"
#include "esp_adc/adc_cali.h"
#include "esp_adc/adc_cali_scheme.h"
#include "router_config.h"
#include "gpio_monitor.h"

static const char *TAG = "gpio_mon";

typedef struct {
    gpio_sample_t *samples;   /* Allocated only when master toggle is ON and slot valid */
    size_t head;              /* Next write index */
    size_t count;             /* Number of valid samples (0..GPIO_HISTORY_MAX) */
    uint32_t last_sample_up;  /* Uptime (s) of last reading */
    bool has_sampled;
    bool read_requested;
    adc_channel_t adc_chan;
    adc_cali_handle_t cali;
    bool cali_ok;
} sensor_runtime_t;

static SemaphoreHandle_t s_mutex = NULL;
static bool s_master_enabled = false;
static gpio_sensor_config_t s_sensors[MAX_GPIO_SENSORS];
static sensor_runtime_t s_rt[MAX_GPIO_SENSORS];
static TaskHandle_t s_task = NULL;
static volatile bool s_task_stop = false;
static adc_oneshot_unit_handle_t s_adc1 = NULL;

void gpio_mon_lock(void)   { if (s_mutex) xSemaphoreTake(s_mutex, portMAX_DELAY); }
void gpio_mon_unlock(void) { if (s_mutex) xSemaphoreGive(s_mutex); }
bool gpio_mon_internal_get_enabled(void) { return s_master_enabled; }
void gpio_mon_internal_set_enabled_flag(bool en) { s_master_enabled = en; }
gpio_sensor_config_t *gpio_mon_internal_get_table(void) { return s_sensors; }

static void csv_path_for(int slot, char *buf, size_t len)
{
    snprintf(buf, len, "/data/gpio_%d.csv", slot);
}

static void sanitize_name(const char *in, char *out, size_t out_len)
{
    size_t j = 0;
    if (!in) in = "";
    for (size_t i = 0; in[i] && j < out_len - 1; i++) {
        char c = in[i];
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '-' || c == '_' || c == ' ';
        out[j++] = ok ? c : '_';
    }
    out[j] = '\0';
    if (j == 0) snprintf(out, out_len, "Sensor");
}

static bool init_adc_cali(adc_channel_t chan, adc_cali_handle_t *out_handle)
{
    esp_err_t ret = ESP_FAIL;
    *out_handle = NULL;
#if ADC_CALI_SCHEME_CURVE_FITTING_SUPPORTED
    adc_cali_curve_fitting_config_t cfg = {
        .unit_id = ADC_UNIT_1,
        .chan = chan,
        .atten = ADC_ATTEN_DB_12,
        .bitwidth = ADC_BITWIDTH_DEFAULT,
    };
    ret = adc_cali_create_scheme_curve_fitting(&cfg, out_handle);
#elif ADC_CALI_SCHEME_LINE_FITTING_SUPPORTED
    (void)chan;
    adc_cali_line_fitting_config_t cfg = {
        .unit_id = ADC_UNIT_1,
        .atten = ADC_ATTEN_DB_12,
        .bitwidth = ADC_BITWIDTH_DEFAULT,
    };
    ret = adc_cali_create_scheme_line_fitting(&cfg, out_handle);
#endif
    return (ret == ESP_OK);
}

static void deinit_adc_cali(adc_cali_handle_t handle)
{
    if (!handle) return;
#if ADC_CALI_SCHEME_CURVE_FITTING_SUPPORTED
    adc_cali_delete_scheme_curve_fitting(handle);
#elif ADC_CALI_SCHEME_LINE_FITTING_SUPPORTED
    adc_cali_delete_scheme_line_fitting(handle);
#endif
}

static void teardown_slot_hw(int slot)
{
    if (s_rt[slot].cali) {
        deinit_adc_cali(s_rt[slot].cali);
        s_rt[slot].cali = NULL;
        s_rt[slot].cali_ok = false;
    }
    free(s_rt[slot].samples);
    s_rt[slot].samples = NULL;
    s_rt[slot].head = 0;
    s_rt[slot].count = 0;
    s_rt[slot].has_sampled = false;
}

static void setup_slot_hw(int slot)
{
    gpio_sensor_config_t *cfg = &s_sensors[slot];
    sensor_runtime_t *rt = &s_rt[slot];
    if (!cfg->valid || !cfg->enabled) return;

    if (!rt->samples) {
        rt->samples = calloc(GPIO_HISTORY_MAX, sizeof(gpio_sample_t));
        if (!rt->samples) {
            ESP_LOGE(TAG, "Slot %d: out of RAM for history buffer", slot);
            return;
        }
        rt->head = 0;
        rt->count = 0;
    }

    if (cfg->mode == GPIO_SENSOR_ANALOG) {
        adc_unit_t unit;
        if (adc_oneshot_io_to_channel(cfg->gpio, &unit, &rt->adc_chan) == ESP_OK && unit == ADC_UNIT_1) {
            if (!s_adc1) {
                adc_oneshot_unit_init_cfg_t ucfg = { .unit_id = ADC_UNIT_1 };
                if (adc_oneshot_new_unit(&ucfg, &s_adc1) != ESP_OK) {
                    ESP_LOGE(TAG, "Failed to init ADC1 unit");
                    return;
                }
            }
            adc_oneshot_chan_cfg_t ccfg = {
                .atten = ADC_ATTEN_DB_12,
                .bitwidth = ADC_BITWIDTH_DEFAULT,
            };
            adc_oneshot_config_channel(s_adc1, rt->adc_chan, &ccfg);
            if (!rt->cali) {
                rt->cali_ok = init_adc_cali(rt->adc_chan, &rt->cali);
            }
        }
    } else {
        gpio_config_t io = {
            .pin_bit_mask = (1ULL << cfg->gpio),
            .mode = GPIO_MODE_INPUT,
            .pull_up_en = GPIO_PULLUP_DISABLE,
            .pull_down_en = GPIO_PULLDOWN_DISABLE,
            .intr_type = GPIO_INTR_DISABLE,
        };
        gpio_config(&io);
    }

#if CONFIG_STORE_HISTORY
    /* Restore persisted CSV samples into RAM ring buffer on startup */
    if (cfg->persist && cfg->interval_sec >= GPIO_MIN_PERSIST_S && rt->count == 0) {
        char path[48];
        csv_path_for(slot, path, sizeof(path));
        FILE *f = fopen(path, "r");
        if (f) {
            char line[96];
            while (fgets(line, sizeof(line), f)) {
                unsigned long u_ts = 0, up = 0;
                unsigned int raw = 0, mv = 0;
                if (sscanf(line, "%lu,%lu,%u,%u", &u_ts, &up, &raw, &mv) == 4) {
                    gpio_sample_t *dst = &rt->samples[rt->head];
                    dst->unix_ts  = (uint32_t)u_ts;
                    dst->uptime_s = (uint32_t)up;
                    dst->raw      = (uint16_t)raw;
                    dst->mv       = (uint16_t)mv;
                    rt->head = (rt->head + 1) % GPIO_HISTORY_MAX;
                    if (rt->count < GPIO_HISTORY_MAX) rt->count++;
                }
            }
            fclose(f);
            ESP_LOGI(TAG, "Restored %u samples for slot %d (%s)", (unsigned)rt->count, slot, cfg->name);
        }
    }
#endif
}

static void record_sample(int slot, const gpio_sample_t *s)
{
#if CONFIG_STORE_HISTORY
    bool do_persist = false;
    char csv_path[48];
#endif
    char sname[GPIO_SENSOR_NAME_LEN];
    int pin = 0;
    uint8_t mode = 0;

    gpio_mon_lock();
    if (s_master_enabled && s_sensors[slot].valid && s_rt[slot].samples) {
        sensor_runtime_t *rt = &s_rt[slot];
        rt->samples[rt->head] = *s;
        rt->head = (rt->head + 1) % GPIO_HISTORY_MAX;
        if (rt->count < GPIO_HISTORY_MAX) rt->count++;
        rt->last_sample_up = s->uptime_s;
        rt->has_sampled = true;

        strlcpy(sname, s_sensors[slot].name, sizeof(sname));
        pin = s_sensors[slot].gpio;
        mode = s_sensors[slot].mode;
#if CONFIG_STORE_HISTORY
        do_persist = (s_sensors[slot].persist && s_sensors[slot].interval_sec >= GPIO_MIN_PERSIST_S);
        if (do_persist) csv_path_for(slot, csv_path, sizeof(csv_path));
#endif
    } else {
        gpio_mon_unlock();
        return;
    }
    gpio_mon_unlock();

    if (mode == GPIO_SENSOR_ANALOG) {
        ESP_LOGI(TAG, "[%s] GPIO%d raw=%u (%u mV)", sname, pin, s->raw, s->mv);
    } else {
        ESP_LOGI(TAG, "[%s] GPIO%d state=%s", sname, pin, s->raw ? "HIGH" : "LOW");
    }

#if CONFIG_STORE_HISTORY
    if (do_persist) {
        struct stat st;
        /* Keep persisted file bounded (~24 KB max) by trimming to current ring buffer */
        if (stat(csv_path, &st) == 0 && st.st_size > 24576) {
            char tmp_path[56];
            snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", csv_path);
            FILE *ft = fopen(tmp_path, "w");
            if (ft) {
                gpio_sample_t batch[16];
                size_t total = gpio_monitor_get_sample_count(slot);
                for (size_t off = 0; off < total; ) {
                    size_t n = gpio_monitor_copy_history_range(slot, off, batch, 16);
                    if (n == 0) break;
                    for (size_t k = 0; k < n; k++) {
                        fprintf(ft, "%lu,%lu,%u,%u\n",
                                (unsigned long)batch[k].unix_ts,
                                (unsigned long)batch[k].uptime_s,
                                (unsigned)batch[k].raw, (unsigned)batch[k].mv);
                    }
                    off += n;
                }
                fclose(ft);
                remove(csv_path);
                rename(tmp_path, csv_path);
            }
        } else {
            FILE *f = fopen(csv_path, "a");
            if (f) {
                fprintf(f, "%lu,%lu,%u,%u\n",
                        (unsigned long)s->unix_ts,
                        (unsigned long)s->uptime_s,
                        (unsigned)s->raw, (unsigned)s->mv);
                fclose(f);
            }
        }
    }
#endif
}

static bool sample_sensor_hw(int slot, gpio_sample_t *out)
{
    gpio_sensor_config_t cfg;
    adc_channel_t chan;
    adc_cali_handle_t cali;
    bool cali_ok;

    gpio_mon_lock();
    if (!s_master_enabled || !s_sensors[slot].valid || !s_sensors[slot].enabled) {
        gpio_mon_unlock();
        return false;
    }
    cfg = s_sensors[slot];
    chan = s_rt[slot].adc_chan;
    cali = s_rt[slot].cali;
    cali_ok = s_rt[slot].cali_ok;
    gpio_mon_unlock();

    time_t now_t = 0;
    time(&now_t);
    out->unix_ts = (now_t > 1577836800) ? (uint32_t)now_t : 0;
    out->uptime_s = (uint32_t)(esp_timer_get_time() / 1000000ULL);

    if (cfg.mode == GPIO_SENSOR_ANALOG) {
        if (!s_adc1) return false;
        int sum = 0, valid_reads = 0;
        for (int r = 0; r < 8; r++) {
            int raw = 0;
            if (adc_oneshot_read(s_adc1, chan, &raw) == ESP_OK) {
                sum += raw;
                valid_reads++;
            }
        }
        if (valid_reads == 0) return false;
        int avg = sum / valid_reads;
        int mv = (avg * 3300) / 4095;
        if (cali_ok && cali) {
            adc_cali_raw_to_voltage(cali, avg, &mv);
        }
        out->raw = (uint16_t)avg;
        out->mv  = (uint16_t)(mv < 0 ? 0 : mv);
    } else {
        int lvl = gpio_get_level((gpio_num_t)cfg.gpio);
        out->raw = (uint16_t)(lvl ? 1 : 0);
        out->mv  = lvl ? 3300 : 0;
    }
    return true;
}

static void gpio_monitor_task(void *arg)
{
    ESP_LOGI(TAG, "GPIO monitor task started");
    while (!s_task_stop) {
        uint32_t up = (uint32_t)(esp_timer_get_time() / 1000000ULL);

        for (int i = 0; i < MAX_GPIO_SENSORS && !s_task_stop; i++) {
            bool due = false;

            gpio_mon_lock();
            if (s_master_enabled && s_sensors[i].valid && s_sensors[i].enabled) {
                if (s_rt[i].read_requested || !s_rt[i].has_sampled ||
                    (up - s_rt[i].last_sample_up >= s_sensors[i].interval_sec)) {
                    due = true;
                    s_rt[i].read_requested = false;
                }
            }
            gpio_mon_unlock();

            if (due) {
                gpio_sample_t sample;
                if (sample_sensor_hw(i, &sample)) {
                    record_sample(i, &sample);
                }
            }
        }
        ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(1000));
    }

    s_task = NULL;
    ESP_LOGI(TAG, "GPIO monitor task stopped");
    vTaskDelete(NULL);
}

static void start_subsystem(void)
{
    gpio_mon_lock();
    for (int i = 0; i < MAX_GPIO_SENSORS; i++) {
        setup_slot_hw(i);
    }
    gpio_mon_unlock();

    if (!s_task) {
        s_task_stop = false;
        xTaskCreate(gpio_monitor_task, "gpio_mon", 4096, NULL, 3, &s_task);
    }
}

static void stop_subsystem(void)
{
    if (s_task) {
        s_task_stop = true;
        xTaskNotifyGive(s_task);
        for (int w = 0; s_task && w < 2000; w += 20) {
            vTaskDelay(pdMS_TO_TICKS(20));
        }
    }

    gpio_mon_lock();
    for (int i = 0; i < MAX_GPIO_SENSORS; i++) {
        teardown_slot_hw(i);
    }
    if (s_adc1) {
        adc_oneshot_del_unit(s_adc1);
        s_adc1 = NULL;
    }
    gpio_mon_unlock();
}

void gpio_monitor_init(void)
{
    if (!s_mutex) {
        s_mutex = xSemaphoreCreateMutex();
    }
    memset(s_sensors, 0, sizeof(s_sensors));
    memset(s_rt, 0, sizeof(s_rt));
    load_gpio_config();

    if (s_master_enabled) {
        start_subsystem();
    } else {
        ESP_LOGI(TAG, "GPIO monitor disabled (0 bytes allocated)");
    }
}

bool gpio_monitor_is_enabled(void)
{
    return s_master_enabled;
}

esp_err_t gpio_monitor_set_enabled(bool enabled)
{
    if (s_master_enabled == enabled) return ESP_OK;

    if (!enabled) {
        s_master_enabled = false;
        stop_subsystem();
    } else {
        s_master_enabled = true;
        start_subsystem();
    }
    return save_gpio_config();
}

static bool validate_gpio_pin(int gpio, gpio_sensor_mode_t mode, char *err_buf, size_t err_len)
{
    if (gpio < 0 || gpio >= GPIO_NUM_MAX || !GPIO_IS_VALID_GPIO(gpio)) {
        snprintf(err_buf, err_len, "Invalid GPIO pin %d", gpio);
        return false;
    }
#if CONFIG_IDF_TARGET_ESP32
    if (gpio >= 6 && gpio <= 11) {
        snprintf(err_buf, err_len, "GPIO %d is used by SPI flash", gpio);
        return false;
    }
#endif
    if (gpio == led_gpio || gpio == led_strip_gpio ||
        gpio == antenna_gpio || gpio == antenna_en_gpio) {
        snprintf(err_buf, err_len, "GPIO %d is already assigned to router LED/antenna", gpio);
        return false;
    }
    if (mode == GPIO_SENSOR_ANALOG) {
        adc_unit_t unit;
        adc_channel_t chan;
        if (adc_oneshot_io_to_channel(gpio, &unit, &chan) != ESP_OK || unit != ADC_UNIT_1) {
            snprintf(err_buf, err_len, "GPIO %d is not an ADC1 analog pin (ADC2 conflicts with Wi-Fi)", gpio);
            return false;
        }
    }
    return true;
}

esp_err_t gpio_monitor_set_sensor(int slot, int gpio, gpio_sensor_mode_t mode,
                                  uint32_t interval_sec, bool persist, const char *name,
                                  char *err_buf, size_t err_len)
{
    char local_err[96] = "";
    if (!err_buf) { err_buf = local_err; err_len = sizeof(local_err); }

    if (!validate_gpio_pin(gpio, mode, err_buf, err_len)) {
        return ESP_ERR_INVALID_ARG;
    }
    if (interval_sec < GPIO_MIN_INTERVAL_S || interval_sec > GPIO_MAX_INTERVAL_S) {
        snprintf(err_buf, err_len, "Interval must be between %d and %d seconds",
                 GPIO_MIN_INTERVAL_S, GPIO_MAX_INTERVAL_S);
        return ESP_ERR_INVALID_ARG;
    }
    if (persist && interval_sec < GPIO_MIN_PERSIST_S) {
        snprintf(err_buf, err_len, "Flash persistence requires interval >= %d seconds", GPIO_MIN_PERSIST_S);
        return ESP_ERR_INVALID_ARG;
    }

    gpio_mon_lock();
    if (slot < 0) {
        for (int i = 0; i < MAX_GPIO_SENSORS; i++) {
            if (!s_sensors[i].valid) { slot = i; break; }
        }
    }
    if (slot < 0 || slot >= MAX_GPIO_SENSORS) {
        gpio_mon_unlock();
        snprintf(err_buf, err_len, "Maximum %d GPIO sensors reached", MAX_GPIO_SENSORS);
        return ESP_ERR_NO_MEM;
    }

    /* Check duplicate pin in another slot */
    for (int i = 0; i < MAX_GPIO_SENSORS; i++) {
        if (i != slot && s_sensors[i].valid && s_sensors[i].gpio == gpio) {
            gpio_mon_unlock();
            snprintf(err_buf, err_len, "GPIO %d is already configured in slot %d", gpio, i);
            return ESP_ERR_INVALID_ARG;
        }
    }

    teardown_slot_hw(slot);

    s_sensors[slot].valid = 1;
    s_sensors[slot].enabled = 1;
    s_sensors[slot].gpio = (int8_t)gpio;
    s_sensors[slot].mode = (uint8_t)mode;
    s_sensors[slot].persist = persist ? 1 : 0;
    s_sensors[slot].interval_sec = interval_sec;
    sanitize_name(name, s_sensors[slot].name, sizeof(s_sensors[slot].name));

    if (s_master_enabled) {
        setup_slot_hw(slot);
        s_rt[slot].read_requested = true;  /* Take initial reading immediately */
    }
    gpio_mon_unlock();

    if (s_master_enabled && s_task) {
        xTaskNotifyGive(s_task);
    }
    return save_gpio_config();
}

esp_err_t gpio_monitor_del_sensor(int slot)
{
    if (slot < 0 || slot >= MAX_GPIO_SENSORS) return ESP_ERR_INVALID_ARG;

    gpio_mon_lock();
    teardown_slot_hw(slot);
    memset(&s_sensors[slot], 0, sizeof(s_sensors[slot]));
    gpio_mon_unlock();

#if CONFIG_STORE_HISTORY
    char path[48];
    csv_path_for(slot, path, sizeof(path));
    remove(path);
#endif
    return save_gpio_config();
}

esp_err_t gpio_monitor_read_now(int slot)
{
    if (!s_master_enabled || slot < 0 || slot >= MAX_GPIO_SENSORS) return ESP_ERR_INVALID_STATE;
    gpio_sample_t s;
    if (!sample_sensor_hw(slot, &s)) return ESP_FAIL;
    record_sample(slot, &s);
    return ESP_OK;
}

esp_err_t gpio_monitor_clear_history(int slot)
{
    if (slot < 0 || slot >= MAX_GPIO_SENSORS) return ESP_ERR_INVALID_ARG;
    gpio_mon_lock();
    s_rt[slot].head = 0;
    s_rt[slot].count = 0;
    s_rt[slot].has_sampled = false;
    gpio_mon_unlock();

#if CONFIG_STORE_HISTORY
    char path[48];
    csv_path_for(slot, path, sizeof(path));
    remove(path);
#endif
    return ESP_OK;
}

bool gpio_monitor_get_sensor(int slot, gpio_sensor_config_t *out)
{
    if (!out || slot < 0 || slot >= MAX_GPIO_SENSORS) return false;
    gpio_mon_lock();
    bool ok = (s_sensors[slot].valid != 0);
    if (ok) *out = s_sensors[slot];
    gpio_mon_unlock();
    return ok;
}

bool gpio_monitor_get_latest(int slot, gpio_sample_t *out)
{
    if (!out || slot < 0 || slot >= MAX_GPIO_SENSORS) return false;
    gpio_mon_lock();
    sensor_runtime_t *rt = &s_rt[slot];
    if (!rt->samples || rt->count == 0) {
        gpio_mon_unlock();
        return false;
    }
    size_t idx = (rt->head + GPIO_HISTORY_MAX - 1) % GPIO_HISTORY_MAX;
    *out = rt->samples[idx];
    gpio_mon_unlock();
    return true;
}

size_t gpio_monitor_get_sample_count(int slot)
{
    if (slot < 0 || slot >= MAX_GPIO_SENSORS) return 0;
    gpio_mon_lock();
    size_t c = s_rt[slot].count;
    gpio_mon_unlock();
    return c;
}

size_t gpio_monitor_copy_history_range(int slot, size_t offset, gpio_sample_t *out, size_t max_count)
{
    if (!out || max_count == 0 || slot < 0 || slot >= MAX_GPIO_SENSORS) return 0;
    gpio_mon_lock();
    sensor_runtime_t *rt = &s_rt[slot];
    if (!rt->samples || offset >= rt->count) {
        gpio_mon_unlock();
        return 0;
    }
    size_t oldest = (rt->count < GPIO_HISTORY_MAX) ? 0 : rt->head;
    size_t avail = rt->count - offset;
    size_t n = (avail < max_count) ? avail : max_count;
    for (size_t i = 0; i < n; i++) {
        size_t idx = (oldest + offset + i) % GPIO_HISTORY_MAX;
        out[i] = rt->samples[idx];
    }
    gpio_mon_unlock();
    return n;
}