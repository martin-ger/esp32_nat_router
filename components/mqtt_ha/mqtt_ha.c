/* MQTT Home Assistant auto-discovery integration.
 *
 * Publishes router telemetry and per-client stats to an MQTT broker
 * with Home Assistant auto-discovery. Compile-time guarded by
 * CONFIG_MQTT_HOMEASSISTANT.
 *
 * SPDX-License-Identifier: MIT
 */

#include "sdkconfig.h"
#ifdef CONFIG_MQTT_HOMEASSISTANT

#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include "mqtt_ha.h"
#include "mqtt_client.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "esp_system.h"
#include "esp_console.h"
#include "argtable3/argtable3.h"
#include "nvs.h"

#include "esp_netif_ip_addr.h"
#include "router_config.h"
#include "client_stats.h"
#include "dhcp_reservations.h"
#include "wifi_config.h"
#include "remote_console.h"

static const char *TAG = "mqtt_ha";

/* ---------- NVS keys (namespace PARAM_NAMESPACE = "esp32_nat") ---------- */
#define NVS_KEY_MQTT_EN    "mqtt_en"
#define NVS_KEY_MQTT_URI   "mqtt_uri"
#define NVS_KEY_MQTT_USER  "mqtt_user"
#define NVS_KEY_MQTT_PASS  "mqtt_pass"
#define NVS_KEY_MQTT_INTV  "mqtt_intv"

/* ---------- MQTT topics ---------- */
#define TOPIC_PREFIX       "esp32_nat_router"
#define TOPIC_STATE        TOPIC_PREFIX "/state"
#define TOPIC_AVAILABILITY TOPIC_PREFIX "/availability"
#define TOPIC_CMD_RESTART  TOPIC_PREFIX "/command/restart"
#define TOPIC_CMD_WEBUI    TOPIC_PREFIX "/command/web_ui"
#define TOPIC_CMD_RC       TOPIC_PREFIX "/command/remote_console"
#define TOPIC_CLIENTS      TOPIC_PREFIX "/clients/"

/* ---------- Config limits ---------- */
#define MQTT_URI_MAX   128
#define MQTT_CRED_MAX   64

/* ---------- Runtime state ---------- */
static esp_mqtt_client_handle_t s_client = NULL;
static esp_timer_handle_t       s_publish_timer = NULL;
static bool s_enabled   = false;
static bool s_connected = false;

static char s_uri[MQTT_URI_MAX]    = "";
static char s_user[MQTT_CRED_MAX]  = "";
static char s_pass[MQTT_CRED_MAX]  = "";
static uint32_t s_interval         = CONFIG_MQTT_DEFAULT_INTERVAL;

/* Cached device identity */
static char s_device_id[32];   /* "esp32_nat_router_AABBCCDDEEFF" */
static char s_mac_str[13];     /* "AABBCCDDEEFF" */

/* ---------- extern globals from main firmware ---------- */
extern uint16_t connect_count;
extern bool     ap_connect;
extern struct dhcp_reservation_entry dhcp_reservations[];

/* ================================================================
 *  Helpers
 * ================================================================ */

static void build_device_id(void)
{
    uint8_t mac[6];
    esp_wifi_get_mac(WIFI_IF_AP, mac);
    snprintf(s_mac_str, sizeof(s_mac_str),
             "%02X%02X%02X%02X%02X%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    snprintf(s_device_id, sizeof(s_device_id),
             "esp32_nat_router_%s", s_mac_str);
}

/* Shared device JSON fragment (embedded in every discovery payload). */
static int device_json(char *buf, size_t len)
{
    char ip_str[16] = "192.168.4.1";
    if (my_ip != 0) {
        snprintf(ip_str, sizeof(ip_str), IPSTR, IP2STR((esp_ip4_addr_t *)&my_ip));
    }
    return snprintf(buf, len,
        "\"dev\":{\"ids\":[\"%s\"],"
        "\"name\":\"%s\","
        "\"sw\":\"%s\","
        "\"cu\":\"http://%s\"}",
        s_device_id, ap_ssid, ROUTER_VERSION, ip_str);
}

/* ================================================================
 *  NVS load / save
 * ================================================================ */

static void load_config(void)
{
    nvs_handle_t h;
    if (nvs_open(PARAM_NAMESPACE, NVS_READONLY, &h) != ESP_OK) return;

    uint8_t en = 0;
    nvs_get_u8(h, NVS_KEY_MQTT_EN, &en);
    s_enabled = (en != 0);

    size_t sz;
    sz = sizeof(s_uri);  nvs_get_str(h, NVS_KEY_MQTT_URI,  s_uri,  &sz);
    sz = sizeof(s_user); nvs_get_str(h, NVS_KEY_MQTT_USER, s_user, &sz);
    sz = sizeof(s_pass); nvs_get_str(h, NVS_KEY_MQTT_PASS, s_pass, &sz);

    nvs_get_u32(h, NVS_KEY_MQTT_INTV, &s_interval);
    if (s_interval < 5)    s_interval = 5;
    if (s_interval > 3600) s_interval = 3600;

    nvs_close(h);
}

static esp_err_t save_u8(const char *key, uint8_t val)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    nvs_set_u8(h, key, val);
    nvs_commit(h);
    nvs_close(h);
    return ESP_OK;
}

static esp_err_t save_u32(const char *key, uint32_t val)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    nvs_set_u32(h, key, val);
    nvs_commit(h);
    nvs_close(h);
    return ESP_OK;
}

static esp_err_t save_str(const char *key, const char *val)
{
    nvs_handle_t h;
    esp_err_t err = nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &h);
    if (err != ESP_OK) return err;
    nvs_set_str(h, key, val);
    nvs_commit(h);
    nvs_close(h);
    return ESP_OK;
}

/* ================================================================
 *  HA Discovery publishing
 * ================================================================ */

static void publish_discovery(void)
{
    if (!s_connected) return;

    char topic[128];
    char payload[768];
    char dev[256];
    device_json(dev, sizeof(dev));

    /* --- Router-level entities --- */

    /* binary_sensor: Uplink Status */
    snprintf(topic, sizeof(topic),
        "homeassistant/binary_sensor/%s/uplink/config", s_device_id);
    snprintf(payload, sizeof(payload),
        "{\"name\":\"Uplink Status\","
        "\"uniq_id\":\"%s_uplink\","
        "\"stat_t\":\"" TOPIC_STATE "\","
        "\"val_tpl\":\"{{value_json.uplink}}\","
        "\"dev_cla\":\"connectivity\","
        "\"pl_on\":\"ON\",\"pl_off\":\"OFF\","
        "\"avty_t\":\"" TOPIC_AVAILABILITY "\","
        "%s}", s_device_id, dev);
    esp_mqtt_client_publish(s_client, topic, payload, 0, 1, 1);

    /* sensor: Connected Clients */
    snprintf(topic, sizeof(topic),
        "homeassistant/sensor/%s/clients/config", s_device_id);
    snprintf(payload, sizeof(payload),
        "{\"name\":\"Connected Clients\","
        "\"uniq_id\":\"%s_clients\","
        "\"stat_t\":\"" TOPIC_STATE "\","
        "\"val_tpl\":\"{{value_json.clients}}\","
        "\"stat_cla\":\"measurement\","
        "\"ic\":\"mdi:wifi\","
        "\"avty_t\":\"" TOPIC_AVAILABILITY "\","
        "%s}", s_device_id, dev);
    esp_mqtt_client_publish(s_client, topic, payload, 0, 1, 1);

    /* sensor: Bytes Sent */
    snprintf(topic, sizeof(topic),
        "homeassistant/sensor/%s/bytes_tx/config", s_device_id);
    snprintf(payload, sizeof(payload),
        "{\"name\":\"Bytes Sent\","
        "\"uniq_id\":\"%s_bytes_tx\","
        "\"stat_t\":\"" TOPIC_STATE "\","
        "\"val_tpl\":\"{{value_json.bytes_tx}}\","
        "\"dev_cla\":\"data_size\","
        "\"stat_cla\":\"total_increasing\","
        "\"unit_of_meas\":\"B\","
        "\"avty_t\":\"" TOPIC_AVAILABILITY "\","
        "%s}", s_device_id, dev);
    esp_mqtt_client_publish(s_client, topic, payload, 0, 1, 1);

    /* sensor: Bytes Received */
    snprintf(topic, sizeof(topic),
        "homeassistant/sensor/%s/bytes_rx/config", s_device_id);
    snprintf(payload, sizeof(payload),
        "{\"name\":\"Bytes Received\","
        "\"uniq_id\":\"%s_bytes_rx\","
        "\"stat_t\":\"" TOPIC_STATE "\","
        "\"val_tpl\":\"{{value_json.bytes_rx}}\","
        "\"dev_cla\":\"data_size\","
        "\"stat_cla\":\"total_increasing\","
        "\"unit_of_meas\":\"B\","
        "\"avty_t\":\"" TOPIC_AVAILABILITY "\","
        "%s}", s_device_id, dev);
    esp_mqtt_client_publish(s_client, topic, payload, 0, 1, 1);

    /* sensor: Free Heap */
    snprintf(topic, sizeof(topic),
        "homeassistant/sensor/%s/free_heap/config", s_device_id);
    snprintf(payload, sizeof(payload),
        "{\"name\":\"Free Heap\","
        "\"uniq_id\":\"%s_free_heap\","
        "\"stat_t\":\"" TOPIC_STATE "\","
        "\"val_tpl\":\"{{value_json.free_heap}}\","
        "\"dev_cla\":\"data_size\","
        "\"stat_cla\":\"measurement\","
        "\"unit_of_meas\":\"B\","
        "\"entity_category\":\"diagnostic\","
        "\"avty_t\":\"" TOPIC_AVAILABILITY "\","
        "%s}", s_device_id, dev);
    esp_mqtt_client_publish(s_client, topic, payload, 0, 1, 1);

    /* sensor: Uptime */
    snprintf(topic, sizeof(topic),
        "homeassistant/sensor/%s/uptime/config", s_device_id);
    snprintf(payload, sizeof(payload),
        "{\"name\":\"Uptime\","
        "\"uniq_id\":\"%s_uptime\","
        "\"stat_t\":\"" TOPIC_STATE "\","
        "\"val_tpl\":\"{{value_json.uptime}}\","
        "\"dev_cla\":\"duration\","
        "\"stat_cla\":\"total_increasing\","
        "\"unit_of_meas\":\"s\","
        "\"entity_category\":\"diagnostic\","
        "\"avty_t\":\"" TOPIC_AVAILABILITY "\","
        "%s}", s_device_id, dev);
    esp_mqtt_client_publish(s_client, topic, payload, 0, 1, 1);

    /* sensor: Uplink RSSI */
    snprintf(topic, sizeof(topic),
        "homeassistant/sensor/%s/rssi/config", s_device_id);
    snprintf(payload, sizeof(payload),
        "{\"name\":\"Uplink RSSI\","
        "\"uniq_id\":\"%s_rssi\","
        "\"stat_t\":\"" TOPIC_STATE "\","
        "\"val_tpl\":\"{{value_json.rssi}}\","
        "\"dev_cla\":\"signal_strength\","
        "\"stat_cla\":\"measurement\","
        "\"unit_of_meas\":\"dBm\","
        "\"entity_category\":\"diagnostic\","
        "\"avty_t\":\"" TOPIC_AVAILABILITY "\","
        "%s}", s_device_id, dev);
    esp_mqtt_client_publish(s_client, topic, payload, 0, 1, 1);

    /* sensor: Uplink SSID */
    snprintf(topic, sizeof(topic),
        "homeassistant/sensor/%s/uplink_ssid/config", s_device_id);
    snprintf(payload, sizeof(payload),
        "{\"name\":\"Uplink SSID\","
        "\"uniq_id\":\"%s_uplink_ssid\","
        "\"stat_t\":\"" TOPIC_STATE "\","
        "\"val_tpl\":\"{{value_json.ssid}}\","
        "\"ic\":\"mdi:wifi-settings\","
        "\"entity_category\":\"diagnostic\","
        "\"avty_t\":\"" TOPIC_AVAILABILITY "\","
        "%s}", s_device_id, dev);
    esp_mqtt_client_publish(s_client, topic, payload, 0, 1, 1);

    /* button: Restart */
    snprintf(topic, sizeof(topic),
        "homeassistant/button/%s/restart/config", s_device_id);
    snprintf(payload, sizeof(payload),
        "{\"name\":\"Restart\","
        "\"uniq_id\":\"%s_restart\","
        "\"cmd_t\":\"" TOPIC_CMD_RESTART "\","
        "\"dev_cla\":\"restart\","
        "\"entity_category\":\"config\","
        "\"avty_t\":\"" TOPIC_AVAILABILITY "\","
        "%s}", s_device_id, dev);
    esp_mqtt_client_publish(s_client, topic, payload, 0, 1, 1);

    /* switch: Web UI */
    snprintf(topic, sizeof(topic),
        "homeassistant/switch/%s/web_ui/config", s_device_id);
    snprintf(payload, sizeof(payload),
        "{\"name\":\"Web UI\","
        "\"uniq_id\":\"%s_web_ui\","
        "\"stat_t\":\"" TOPIC_STATE "\","
        "\"val_tpl\":\"{{value_json.web_ui}}\","
        "\"cmd_t\":\"" TOPIC_CMD_WEBUI "\","
        "\"ic\":\"mdi:web\","
        "\"entity_category\":\"config\","
        "\"avty_t\":\"" TOPIC_AVAILABILITY "\","
        "%s}", s_device_id, dev);
    esp_mqtt_client_publish(s_client, topic, payload, 0, 1, 1);

    /* switch: Remote Console */
    snprintf(topic, sizeof(topic),
        "homeassistant/switch/%s/remote_console/config", s_device_id);
    snprintf(payload, sizeof(payload),
        "{\"name\":\"Remote Console\","
        "\"uniq_id\":\"%s_remote_console\","
        "\"stat_t\":\"" TOPIC_STATE "\","
        "\"val_tpl\":\"{{value_json.remote_console}}\","
        "\"cmd_t\":\"" TOPIC_CMD_RC "\","
        "\"ic\":\"mdi:console\","
        "\"entity_category\":\"config\","
        "\"avty_t\":\"" TOPIC_AVAILABILITY "\","
        "%s}", s_device_id, dev);
    esp_mqtt_client_publish(s_client, topic, payload, 0, 1, 1);

    /* --- Per-client entities (DHCP reservations only) --- */
    for (int i = 0; i < MAX_DHCP_RESERVATIONS; i++) {
        if (!dhcp_reservations[i].valid) continue;

        const struct dhcp_reservation_entry *r = &dhcp_reservations[i];
        char cmac[13];
        snprintf(cmac, sizeof(cmac), "%02X%02X%02X%02X%02X%02X",
                 r->mac[0], r->mac[1], r->mac[2],
                 r->mac[3], r->mac[4], r->mac[5]);

        /* Use reservation name if set, otherwise MAC */
        const char *name = (r->name[0] != '\0') ? r->name : cmac;
        char client_state_topic[64];
        snprintf(client_state_topic, sizeof(client_state_topic),
                 TOPIC_CLIENTS "%s", cmac);

        /* binary_sensor: Presence */
        snprintf(topic, sizeof(topic),
            "homeassistant/binary_sensor/%s/%s_presence/config",
            s_device_id, cmac);
        snprintf(payload, sizeof(payload),
            "{\"name\":\"%s Presence\","
            "\"uniq_id\":\"%s_%s_presence\","
            "\"stat_t\":\"%s\","
            "\"val_tpl\":\"{{value_json.present}}\","
            "\"dev_cla\":\"presence\","
            "\"pl_on\":\"ON\",\"pl_off\":\"OFF\","
            "\"avty_t\":\"" TOPIC_AVAILABILITY "\","
            "%s}", name, s_device_id, cmac, client_state_topic, dev);
        esp_mqtt_client_publish(s_client, topic, payload, 0, 1, 1);

        /* sensor: TX */
        snprintf(topic, sizeof(topic),
            "homeassistant/sensor/%s/%s_tx/config", s_device_id, cmac);
        snprintf(payload, sizeof(payload),
            "{\"name\":\"%s TX\","
            "\"uniq_id\":\"%s_%s_tx\","
            "\"stat_t\":\"%s\","
            "\"val_tpl\":\"{{value_json.tx}}\","
            "\"dev_cla\":\"data_size\","
            "\"stat_cla\":\"total_increasing\","
            "\"unit_of_meas\":\"B\","
            "\"avty_t\":\"" TOPIC_AVAILABILITY "\","
            "%s}", name, s_device_id, cmac, client_state_topic, dev);
        esp_mqtt_client_publish(s_client, topic, payload, 0, 1, 1);

        /* sensor: RX */
        snprintf(topic, sizeof(topic),
            "homeassistant/sensor/%s/%s_rx/config", s_device_id, cmac);
        snprintf(payload, sizeof(payload),
            "{\"name\":\"%s RX\","
            "\"uniq_id\":\"%s_%s_rx\","
            "\"stat_t\":\"%s\","
            "\"val_tpl\":\"{{value_json.rx}}\","
            "\"dev_cla\":\"data_size\","
            "\"stat_cla\":\"total_increasing\","
            "\"unit_of_meas\":\"B\","
            "\"avty_t\":\"" TOPIC_AVAILABILITY "\","
            "%s}", name, s_device_id, cmac, client_state_topic, dev);
        esp_mqtt_client_publish(s_client, topic, payload, 0, 1, 1);

        /* sensor: RSSI */
        snprintf(topic, sizeof(topic),
            "homeassistant/sensor/%s/%s_rssi/config", s_device_id, cmac);
        snprintf(payload, sizeof(payload),
            "{\"name\":\"%s RSSI\","
            "\"uniq_id\":\"%s_%s_rssi\","
            "\"stat_t\":\"%s\","
            "\"val_tpl\":\"{{value_json.rssi}}\","
            "\"dev_cla\":\"signal_strength\","
            "\"stat_cla\":\"measurement\","
            "\"unit_of_meas\":\"dBm\","
            "\"avty_t\":\"" TOPIC_AVAILABILITY "\","
            "%s}", name, s_device_id, cmac, client_state_topic, dev);
        esp_mqtt_client_publish(s_client, topic, payload, 0, 1, 1);
    }

    ESP_LOGI(TAG, "Discovery configs published");
}

/* ================================================================
 *  Periodic state publish
 * ================================================================ */

static bool is_web_ui_enabled(void)
{
    char *lock = NULL;
    get_config_param_str("lock", &lock);
    bool enabled = (lock == NULL || strcmp(lock, "0") == 0);
    if (lock) free(lock);
    return enabled;
}

static void publish_state(void *arg)
{
    if (!s_connected) return;

    /* Get uplink info (RSSI + SSID) */
    wifi_ap_record_t ap_info;
    int8_t rssi = 0;
    char uplink_ssid[33] = "";
    if (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK) {
        rssi = ap_info.rssi;
        strncpy(uplink_ssid, (const char *)ap_info.ssid, sizeof(uplink_ssid) - 1);
    }

    /* Router-level state */
    char payload[384];
    snprintf(payload, sizeof(payload),
        "{\"uplink\":\"%s\",\"clients\":%u,"
        "\"bytes_tx\":%" PRIu64 ",\"bytes_rx\":%" PRIu64 ","
        "\"free_heap\":%" PRIu32 ",\"uptime\":%" PRIu32 ","
        "\"rssi\":%d,\"ssid\":\"%s\","
        "\"web_ui\":\"%s\",\"remote_console\":\"%s\"}",
        ap_connect ? "ON" : "OFF",
        connect_count,
        get_sta_bytes_sent(),
        get_sta_bytes_received(),
        (uint32_t)esp_get_free_heap_size(),
        get_uptime_seconds(),
        rssi, uplink_ssid,
        is_web_ui_enabled() ? "ON" : "OFF",
        remote_console_is_enabled() ? "ON" : "OFF");
    esp_mqtt_client_publish(s_client, TOPIC_STATE, payload, 0, 0, 1);

    /* Get AP station list for per-client RSSI */
    wifi_sta_list_t sta_list;
    esp_wifi_ap_get_sta_list(&sta_list);

    /* Per-client state (DHCP reservations only) */
    client_stats_entry_t stats[CLIENT_STATS_MAX];
    int nstats = client_stats_get_all(stats, CLIENT_STATS_MAX);

    for (int i = 0; i < MAX_DHCP_RESERVATIONS; i++) {
        if (!dhcp_reservations[i].valid) continue;

        const struct dhcp_reservation_entry *r = &dhcp_reservations[i];
        char cmac[13];
        snprintf(cmac, sizeof(cmac), "%02X%02X%02X%02X%02X%02X",
                 r->mac[0], r->mac[1], r->mac[2],
                 r->mac[3], r->mac[4], r->mac[5]);

        /* Find matching stats entry */
        uint64_t tx = 0, rx = 0;
        bool present = false;
        for (int j = 0; j < nstats; j++) {
            if (memcmp(stats[j].mac, r->mac, 6) == 0) {
                tx = stats[j].bytes_sent;
                rx = stats[j].bytes_received;
                present = (stats[j].connected != 0);
                break;
            }
        }

        /* Find RSSI from AP station list */
        int8_t client_rssi = 0;
        for (int j = 0; j < sta_list.num; j++) {
            if (memcmp(sta_list.sta[j].mac, r->mac, 6) == 0) {
                client_rssi = sta_list.sta[j].rssi;
                break;
            }
        }

        char topic[64];
        snprintf(topic, sizeof(topic), TOPIC_CLIENTS "%s", cmac);
        snprintf(payload, sizeof(payload),
            "{\"present\":\"%s\",\"tx\":%" PRIu64 ",\"rx\":%" PRIu64 ",\"rssi\":%d}",
            present ? "ON" : "OFF", tx, rx, client_rssi);
        esp_mqtt_client_publish(s_client, topic, payload, 0, 0, 1);
    }
}

/* ================================================================
 *  MQTT event handler
 * ================================================================ */

static void mqtt_event_handler(void *arg, esp_event_base_t base,
                                int32_t event_id, void *event_data)
{
    esp_mqtt_event_handle_t event = (esp_mqtt_event_handle_t)event_data;

    switch (event_id) {
    case MQTT_EVENT_CONNECTED:
        ESP_LOGI(TAG, "Connected to broker");
        s_connected = true;
        /* Publish online availability */
        esp_mqtt_client_publish(s_client, TOPIC_AVAILABILITY, "online", 0, 1, 1);
        /* Subscribe to command topics */
        esp_mqtt_client_subscribe(s_client, TOPIC_CMD_RESTART, 1);
        esp_mqtt_client_subscribe(s_client, TOPIC_CMD_WEBUI, 1);
        esp_mqtt_client_subscribe(s_client, TOPIC_CMD_RC, 1);
        /* Publish HA discovery */
        publish_discovery();
        /* Publish initial state */
        publish_state(NULL);
        break;

    case MQTT_EVENT_DISCONNECTED:
        ESP_LOGW(TAG, "Disconnected from broker");
        s_connected = false;
        break;

    case MQTT_EVENT_DATA:
        if (event->topic_len > 0 && event->topic != NULL) {
            if (event->topic_len == (int)strlen(TOPIC_CMD_RESTART) &&
                memcmp(event->topic, TOPIC_CMD_RESTART, event->topic_len) == 0) {
                ESP_LOGW(TAG, "Restart command received via MQTT");
                esp_restart();
            }
            if (event->topic_len == (int)strlen(TOPIC_CMD_WEBUI) &&
                memcmp(event->topic, TOPIC_CMD_WEBUI, event->topic_len) == 0) {
                bool on = (event->data_len >= 2 &&
                           strncasecmp(event->data, "ON", 2) == 0);
                ESP_LOGI(TAG, "Web UI %s via MQTT", on ? "enabled" : "disabled");
                nvs_handle_t h;
                if (nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &h) == ESP_OK) {
                    nvs_set_str(h, "lock", on ? "0" : "1");
                    nvs_commit(h);
                    nvs_close(h);
                }
                /* Publish updated state immediately */
                publish_state(NULL);
            }
            if (event->topic_len == (int)strlen(TOPIC_CMD_RC) &&
                memcmp(event->topic, TOPIC_CMD_RC, event->topic_len) == 0) {
                bool on = (event->data_len >= 2 &&
                           strncasecmp(event->data, "ON", 2) == 0);
                ESP_LOGI(TAG, "Remote console %s via MQTT", on ? "enabled" : "disabled");
                if (on) {
                    remote_console_enable();
                } else {
                    remote_console_disable();
                }
                publish_state(NULL);
            }
        }
        break;

    case MQTT_EVENT_ERROR:
        ESP_LOGE(TAG, "MQTT error type: %d", event->error_handle->error_type);
        break;

    default:
        break;
    }
}

/* ================================================================
 *  Start / Stop
 * ================================================================ */

esp_err_t mqtt_ha_start(void)
{
    if (s_client != NULL) {
        ESP_LOGW(TAG, "Already running");
        return ESP_OK;
    }

    if (s_uri[0] == '\0') {
        ESP_LOGE(TAG, "No broker URI configured. Use: mqtt broker <uri>");
        return ESP_ERR_INVALID_STATE;
    }

    build_device_id();

    esp_mqtt_client_config_t cfg = {
        .broker.address.uri = s_uri,
        .credentials.username = s_user[0] ? s_user : NULL,
        .credentials.authentication.password = s_pass[0] ? s_pass : NULL,
        .session.keepalive = 60,
        .session.last_will = {
            .topic = TOPIC_AVAILABILITY,
            .msg = "offline",
            .msg_len = 7,
            .qos = 1,
            .retain = 1,
        },
        .buffer.size = CONFIG_MQTT_BUFFER_SIZE,
        .buffer.out_size = CONFIG_MQTT_BUFFER_SIZE,
    };

    s_client = esp_mqtt_client_init(&cfg);
    if (s_client == NULL) {
        ESP_LOGE(TAG, "Failed to init MQTT client");
        return ESP_FAIL;
    }

    esp_mqtt_client_register_event(s_client, ESP_EVENT_ANY_ID,
                                    mqtt_event_handler, NULL);
    esp_err_t err = esp_mqtt_client_start(s_client);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start MQTT client: %s", esp_err_to_name(err));
        esp_mqtt_client_destroy(s_client);
        s_client = NULL;
        return err;
    }

    /* Create periodic publish timer */
    if (s_publish_timer == NULL) {
        esp_timer_create_args_t timer_args = {
            .callback = publish_state,
            .name = "mqtt_publish",
        };
        esp_timer_create(&timer_args, &s_publish_timer);
    }
    esp_timer_start_periodic(s_publish_timer,
                              (uint64_t)s_interval * 1000000ULL);

    ESP_LOGI(TAG, "Started (broker: %s, interval: %" PRIu32 "s)", s_uri, s_interval);
    return ESP_OK;
}

esp_err_t mqtt_ha_stop(void)
{
    if (s_publish_timer != NULL) {
        esp_timer_stop(s_publish_timer);
    }

    if (s_client != NULL) {
        /* Publish offline before disconnecting */
        if (s_connected) {
            esp_mqtt_client_publish(s_client, TOPIC_AVAILABILITY, "offline", 0, 1, 1);
            vTaskDelay(pdMS_TO_TICKS(200)); /* brief delay to let it send */
        }
        esp_mqtt_client_stop(s_client);
        esp_mqtt_client_destroy(s_client);
        s_client = NULL;
        s_connected = false;
    }

    ESP_LOGI(TAG, "Stopped");
    return ESP_OK;
}

void mqtt_ha_rediscover(void)
{
    if (!s_connected) {
        ESP_LOGW(TAG, "Not connected — cannot rediscover");
        return;
    }
    publish_discovery();
}

const char *mqtt_ha_get_status(void)
{
    if (!s_enabled)   return "disabled";
    if (s_connected)  return "connected";
    return "disconnected";
}

/* ================================================================
 *  CLI commands
 * ================================================================ */

static struct {
    struct arg_str *action;
    struct arg_str *arg1;
    struct arg_str *arg2;
    struct arg_end *end;
} mqtt_args;

static int mqtt_cmd(int argc, char **argv)
{
    int nerrors = arg_parse(argc, argv, (void **)&mqtt_args);
    if (nerrors != 0) {
        arg_print_errors(stderr, mqtt_args.end, argv[0]);
        return 1;
    }

    const char *action = mqtt_args.action->sval[0];

    if (strcmp(action, "status") == 0) {
        printf("MQTT HA:   %s\n", mqtt_ha_get_status());
        printf("Broker:    %s\n", s_uri[0] ? s_uri : "(not set)");
        printf("User:      %s\n", s_user[0] ? s_user : "(not set)");
        printf("Interval:  %" PRIu32 "s\n", s_interval);
        if (s_connected) {
            printf("Device ID: %s\n", s_device_id);
        }
        return 0;
    }

    if (strcmp(action, "enable") == 0) {
        s_enabled = true;
        save_u8(NVS_KEY_MQTT_EN, 1);
        esp_err_t err = mqtt_ha_start();
        if (err != ESP_OK) {
            printf("Failed to start: %s\n", esp_err_to_name(err));
            return 1;
        }
        printf("MQTT HA enabled and started\n");
        return 0;
    }

    if (strcmp(action, "disable") == 0) {
        s_enabled = false;
        save_u8(NVS_KEY_MQTT_EN, 0);
        mqtt_ha_stop();
        printf("MQTT HA disabled\n");
        return 0;
    }

    if (strcmp(action, "broker") == 0) {
        if (mqtt_args.arg1->count == 0) {
            printf("Usage: mqtt broker <uri>\n");
            return 1;
        }
        strncpy(s_uri, mqtt_args.arg1->sval[0], sizeof(s_uri) - 1);
        s_uri[sizeof(s_uri) - 1] = '\0';
        save_str(NVS_KEY_MQTT_URI, s_uri);
        printf("Broker set to: %s\n", s_uri);
        return 0;
    }

    if (strcmp(action, "user") == 0) {
        if (mqtt_args.arg1->count == 0 || mqtt_args.arg2->count == 0) {
            printf("Usage: mqtt user <username> <password>\n");
            return 1;
        }
        strncpy(s_user, mqtt_args.arg1->sval[0], sizeof(s_user) - 1);
        s_user[sizeof(s_user) - 1] = '\0';
        strncpy(s_pass, mqtt_args.arg2->sval[0], sizeof(s_pass) - 1);
        s_pass[sizeof(s_pass) - 1] = '\0';
        save_str(NVS_KEY_MQTT_USER, s_user);
        save_str(NVS_KEY_MQTT_PASS, s_pass);
        printf("MQTT credentials set\n");
        return 0;
    }

    if (strcmp(action, "interval") == 0) {
        if (mqtt_args.arg1->count == 0) {
            printf("Usage: mqtt interval <seconds>\n");
            return 1;
        }
        int val = atoi(mqtt_args.arg1->sval[0]);
        if (val < 5 || val > 3600) {
            printf("Interval must be 5-3600 seconds\n");
            return 1;
        }
        s_interval = (uint32_t)val;
        save_u32(NVS_KEY_MQTT_INTV, s_interval);
        printf("Publish interval set to %" PRIu32 "s\n", s_interval);
        /* Restart timer if running */
        if (s_publish_timer != NULL && s_client != NULL) {
            esp_timer_stop(s_publish_timer);
            esp_timer_start_periodic(s_publish_timer,
                                      (uint64_t)s_interval * 1000000ULL);
        }
        return 0;
    }

    if (strcmp(action, "rediscover") == 0) {
        mqtt_ha_rediscover();
        printf("Discovery configs re-published\n");
        return 0;
    }

    printf("Unknown action: %s\n", action);
    printf("Usage: mqtt <status|enable|disable|broker|user|interval|rediscover>\n");
    return 1;
}

static void register_mqtt_cmd(void)
{
    mqtt_args.action = arg_str1(NULL, NULL, "<action>",
        "status|enable|disable|broker|user|interval|rediscover");
    mqtt_args.arg1   = arg_str0(NULL, NULL, "<arg1>", "URI, username, or seconds");
    mqtt_args.arg2   = arg_str0(NULL, NULL, "<arg2>", "password");
    mqtt_args.end    = arg_end(3);

    const esp_console_cmd_t cmd = {
        .command = "mqtt",
        .help = "MQTT Home Assistant integration",
        .hint = NULL,
        .func = &mqtt_cmd,
        .argtable = &mqtt_args,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&cmd));
}

/* ================================================================
 *  Init (called from app_main)
 * ================================================================ */

void mqtt_ha_init(void)
{
    load_config();
    register_mqtt_cmd();

    ESP_LOGI(TAG, "Initialized (enabled=%d, broker=%s)",
             s_enabled, s_uri[0] ? s_uri : "none");

    if (s_enabled && s_uri[0] != '\0') {
        mqtt_ha_start();
    }
}

#endif /* CONFIG_MQTT_HOMEASSISTANT */
