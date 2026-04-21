#include "fdb.h"

#if CONFIG_REPEATER_MODE

#include <string.h>
#include "esp_log.h"
#include "esp_timer.h"
#include "repeater_config.h"

static const char *TAG = "fdb";

typedef struct {
    uint32_t ip;
    uint8_t  mac[6];
    int64_t  expires_us;
    bool     valid;
} fdb_entry_t;

static fdb_entry_t s_fdb[REPEATER_FDB_SIZE];

static bool mac_eq(const uint8_t a[6], const uint8_t b[6]) {
    return memcmp(a, b, 6) == 0;
}

static bool mac_is_zero(const uint8_t m[6]) {
    for (int i = 0; i < 6; i++) if (m[i]) return false;
    return true;
}

void fdb_init(void) {
    memset(s_fdb, 0, sizeof(s_fdb));
    ESP_LOGI(TAG, "FDB initialized, capacity=%d", REPEATER_FDB_SIZE);
}

void fdb_learn(uint32_t ip, const uint8_t mac[6], uint32_t ttl_seconds) {
    if (ip == 0 || mac_is_zero(mac)) return;

    int64_t now = esp_timer_get_time();
    int64_t ttl_us = (int64_t)ttl_seconds * 1000000LL;
    int free_slot = -1;
    int oldest_slot = 0;
    int64_t oldest_exp = INT64_MAX;

    for (int i = 0; i < REPEATER_FDB_SIZE; i++) {
        fdb_entry_t *e = &s_fdb[i];
        if (e->valid && (e->ip == ip || mac_eq(e->mac, mac))) {
            e->ip = ip;
            memcpy(e->mac, mac, 6);
            e->expires_us = now + ttl_us;
            return;
        }
        if (!e->valid || e->expires_us <= now) {
            if (free_slot < 0) free_slot = i;
        }
        if (e->expires_us < oldest_exp) {
            oldest_exp = e->expires_us;
            oldest_slot = i;
        }
    }

    int slot = (free_slot >= 0) ? free_slot : oldest_slot;
    fdb_entry_t *e = &s_fdb[slot];
    e->ip = ip;
    memcpy(e->mac, mac, 6);
    e->expires_us = now + ttl_us;
    e->valid = true;
    ESP_LOGD(TAG, "learn slot=%d ip=0x%08" PRIx32 " mac=%02x:%02x:%02x:%02x:%02x:%02x",
             slot, ip, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

bool fdb_lookup_by_ip(uint32_t ip, uint8_t mac_out[6]) {
    int64_t now = esp_timer_get_time();
    for (int i = 0; i < REPEATER_FDB_SIZE; i++) {
        fdb_entry_t *e = &s_fdb[i];
        if (e->valid && e->expires_us > now && e->ip == ip) {
            memcpy(mac_out, e->mac, 6);
            return true;
        }
    }
    return false;
}

uint32_t fdb_lookup_by_mac(const uint8_t mac[6]) {
    int64_t now = esp_timer_get_time();
    for (int i = 0; i < REPEATER_FDB_SIZE; i++) {
        fdb_entry_t *e = &s_fdb[i];
        if (e->valid && e->expires_us > now && mac_eq(e->mac, mac)) {
            return e->ip;
        }
    }
    return 0;
}

void fdb_age(void) {
    int64_t now = esp_timer_get_time();
    for (int i = 0; i < REPEATER_FDB_SIZE; i++) {
        fdb_entry_t *e = &s_fdb[i];
        if (e->valid && e->expires_us <= now) {
            e->valid = false;
        }
    }
}

void fdb_clear(void) {
    memset(s_fdb, 0, sizeof(s_fdb));
}

int fdb_snapshot(fdb_snapshot_entry_t *out, int max) {
    int64_t now = esp_timer_get_time();
    int n = 0;
    for (int i = 0; i < REPEATER_FDB_SIZE && n < max; i++) {
        fdb_entry_t *e = &s_fdb[i];
        if (!e->valid) continue;
        out[n].ip = e->ip;
        memcpy(out[n].mac, e->mac, 6);
        out[n].ttl_remaining = (int32_t)((e->expires_us - now) / 1000000);
        n++;
    }
    return n;
}

#endif
