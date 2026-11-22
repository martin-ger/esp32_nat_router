/* NVS persistence for GPIO Monitor configuration */

#include <string.h>
#include "esp_log.h"
#include "nvs.h"
#include "router_config.h"
#include "wifi_config.h"
#include "gpio_monitor.h"

static const char *TAG = "gpio_nvs";

/* Internal accessors in gpio_monitor.c */
extern bool gpio_mon_internal_get_enabled(void);
extern void gpio_mon_internal_set_enabled_flag(bool en);
extern gpio_sensor_config_t *gpio_mon_internal_get_table(void);
extern void gpio_mon_lock(void);
extern void gpio_mon_unlock(void);

esp_err_t save_gpio_config(void)
{
    gpio_sensor_config_t snapshot[MAX_GPIO_SENSORS];
    bool en;

    gpio_mon_lock();
    en = gpio_mon_internal_get_enabled();
    memcpy(snapshot, gpio_mon_internal_get_table(), sizeof(snapshot));
    gpio_mon_unlock();

    nvs_handle_t nvs;
    esp_err_t err = nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) return err;

    err = nvs_set_i32(nvs, "gpio_en", en ? 1 : 0);
    if (err == ESP_OK) {
        err = nvs_set_blob(nvs, "gpio_cfg", snapshot, sizeof(snapshot));
    }
    if (err == ESP_OK) {
        err = nvs_commit(nvs);
    }
    nvs_close(nvs);

    if (err == ESP_OK) {
        ESP_LOGI(TAG, "GPIO config saved to NVS");
    } else {
        ESP_LOGE(TAG, "Failed saving GPIO config: %s", esp_err_to_name(err));
    }
    return err;
}

esp_err_t load_gpio_config(void)
{
    nvs_handle_t nvs;
    esp_err_t err = nvs_open(PARAM_NAMESPACE, NVS_READONLY, &nvs);
    if (err != ESP_OK) return err;

    int32_t en = 0;
    if (nvs_get_i32(nvs, "gpio_en", &en) == ESP_OK) {
        gpio_mon_internal_set_enabled_flag(en != 0);
    }

    gpio_sensor_config_t loaded[MAX_GPIO_SENSORS];
    size_t len = sizeof(loaded);
    if (nvs_get_blob(nvs, "gpio_cfg", loaded, &len) == ESP_OK && len == sizeof(loaded)) {
        gpio_mon_lock();
        memcpy(gpio_mon_internal_get_table(), loaded, sizeof(loaded));
        gpio_mon_unlock();
    }

    nvs_close(nvs);
    return ESP_OK;
}