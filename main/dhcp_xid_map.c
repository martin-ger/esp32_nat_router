#include "dhcp_xid_map.h"

#if CONFIG_REPEATER_MODE

#include <string.h>
#include "esp_log.h"
#include "esp_timer.h"
#include "repeater_config.h"

static const char *TAG = "xidmap";

typedef struct {
    uint32_t xid;
    uint8_t  chaddr[6];
    int64_t  expires_us;
    bool     valid;
} xid_entry_t;

static xid_entry_t s_map[REPEATER_XID_MAP_SIZE];

void dhcp_xid_map_init(void) {
    memset(s_map, 0, sizeof(s_map));
    ESP_LOGI(TAG, "XID map initialized, capacity=%d", REPEATER_XID_MAP_SIZE);
}

void dhcp_xid_map_insert(uint32_t xid, const uint8_t chaddr[6]) {
    int64_t now = esp_timer_get_time();
    int64_t ttl_us = (int64_t)REPEATER_XID_TTL_S * 1000000LL;
    int free_slot = -1;
    int oldest_slot = 0;
    int64_t oldest_exp = INT64_MAX;

    for (int i = 0; i < REPEATER_XID_MAP_SIZE; i++) {
        xid_entry_t *e = &s_map[i];
        if (e->valid && e->xid == xid) {
            memcpy(e->chaddr, chaddr, 6);
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
    xid_entry_t *e = &s_map[slot];
    e->xid = xid;
    memcpy(e->chaddr, chaddr, 6);
    e->expires_us = now + ttl_us;
    e->valid = true;
    ESP_LOGD(TAG, "insert slot=%d xid=0x%08" PRIx32, slot, xid);
}

bool dhcp_xid_map_lookup(uint32_t xid, uint8_t chaddr_out[6]) {
    int64_t now = esp_timer_get_time();
    for (int i = 0; i < REPEATER_XID_MAP_SIZE; i++) {
        xid_entry_t *e = &s_map[i];
        if (e->valid && e->expires_us > now && e->xid == xid) {
            memcpy(chaddr_out, e->chaddr, 6);
            return true;
        }
    }
    return false;
}

void dhcp_xid_map_age(void) {
    int64_t now = esp_timer_get_time();
    for (int i = 0; i < REPEATER_XID_MAP_SIZE; i++) {
        xid_entry_t *e = &s_map[i];
        if (e->valid && e->expires_us <= now) {
            e->valid = false;
        }
    }
}

int dhcp_xid_map_snapshot(dhcp_xid_snapshot_entry_t *out, int max) {
    int64_t now = esp_timer_get_time();
    int n = 0;
    for (int i = 0; i < REPEATER_XID_MAP_SIZE && n < max; i++) {
        xid_entry_t *e = &s_map[i];
        if (!e->valid) continue;
        out[n].xid = e->xid;
        memcpy(out[n].chaddr, e->chaddr, 6);
        out[n].ttl_remaining = (int32_t)((e->expires_us - now) / 1000000);
        n++;
    }
    return n;
}

#endif
