/* ACL firewall rule persistence (NVS).
 *
 * Saves and loads ACL rules to/from NVS flash storage.
 * Thread-safe: acquires the ACL lock when accessing rule data.
 */

#include <string.h>
#include "esp_log.h"
#include "nvs.h"
#include "acl.h"
#include "router_globals.h"

static const char *TAG = "acl_nvs";

esp_err_t save_acl_rules(void) {
    esp_err_t err;
    nvs_handle_t nvs;

    /* Snapshot all ACL lists under the lock, then write to NVS outside
     * the lock to avoid blocking packet processing during flash I/O. */
    acl_entry_t snapshot[MAX_ACL_LISTS][MAX_ACL_ENTRIES];
    acl_lock();
    for (int i = 0; i < MAX_ACL_LISTS; i++) {
        acl_entry_t* rules = acl_get_rules(i);
        if (rules != NULL) {
            memcpy(snapshot[i], rules, sizeof(acl_entry_t) * MAX_ACL_ENTRIES);
        }
    }
    acl_unlock();

    err = nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) {
        return err;
    }

    const char* acl_keys[MAX_ACL_LISTS] = {"acl_0", "acl_1", "acl_2", "acl_3"};
    for (int i = 0; i < MAX_ACL_LISTS; i++) {
        err = nvs_set_blob(nvs, acl_keys[i], snapshot[i], sizeof(acl_entry_t) * MAX_ACL_ENTRIES);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Failed to save ACL list %d: %s", i, esp_err_to_name(err));
        }
    }

    err = nvs_commit(nvs);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "ACL rules saved to NVS");
    }
    nvs_close(nvs);
    return err;
}

esp_err_t load_acl_rules(void) {
    esp_err_t err;
    nvs_handle_t nvs;
    size_t len;

    /* Initialize ACL subsystem first */
    acl_init();

    err = nvs_open(PARAM_NAMESPACE, NVS_READONLY, &nvs);
    if (err != ESP_OK) {
        return err;
    }

    /* Load each ACL list */
    const char* acl_keys[MAX_ACL_LISTS] = {"acl_0", "acl_1", "acl_2", "acl_3"};
    acl_lock();
    for (int i = 0; i < MAX_ACL_LISTS; i++) {
        acl_entry_t* rules = acl_get_rules(i);
        if (rules == NULL) continue;

        len = sizeof(acl_entry_t) * MAX_ACL_ENTRIES;
        err = nvs_get_blob(nvs, acl_keys[i], rules, &len);
        if (err == ESP_OK) {
            /* Count loaded rules and reset hit counters */
            int count = 0;
            for (int j = 0; j < MAX_ACL_ENTRIES; j++) {
                if (rules[j].valid) {
                    count++;
                    rules[j].hit_count = 0;  /* Reset hit counter on boot */
                }
            }
            if (count > 0) {
                ESP_LOGI(TAG, "Loaded %d ACL rules for %s", count, acl_get_name(i));
            }
        } else if (err != ESP_ERR_NVS_NOT_FOUND) {
            ESP_LOGW(TAG, "Failed to load ACL list %d: %s", i, esp_err_to_name(err));
        }
    }
    acl_unlock();

    nvs_close(nvs);
    return ESP_OK;
}
