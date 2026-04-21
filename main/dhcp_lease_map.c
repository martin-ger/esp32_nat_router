#include "dhcp_lease_map.h"

#if CONFIG_REPEATER_MODE

#include <string.h>
#include <strings.h>
#include <inttypes.h>
#include "esp_log.h"
#include "esp_timer.h"
#include "repeater_config.h"

static const char *TAG = "lease_map";

#define DEFAULT_LEASE_TTL_S  3600

static dhcp_lease_entry_t s_map[DHCP_LEASE_MAP_SIZE];

void dhcp_lease_map_init(void) {
    memset(s_map, 0, sizeof(s_map));
    ESP_LOGI(TAG, "Lease map initialized, capacity=%d", DHCP_LEASE_MAP_SIZE);
}

void dhcp_lease_map_update(const uint8_t mac[6], uint32_t ip,
                           const char *hostname, uint32_t lease_sec) {
    int64_t now = esp_timer_get_time();
    uint32_t ttl = lease_sec > 0 ? lease_sec : DEFAULT_LEASE_TTL_S;
    int64_t expires = now + (int64_t)ttl * 1000000LL;

    /* Update existing entry if MAC matches */
    for (int i = 0; i < DHCP_LEASE_MAP_SIZE; i++) {
        dhcp_lease_entry_t *e = &s_map[i];
        if (e->valid && memcmp(e->mac, mac, 6) == 0) {
            e->ip = ip;
            e->expires_us = expires;
            if (hostname && hostname[0]) {
                strncpy(e->hostname, hostname, DHCP_HOSTNAME_MAX - 1);
                e->hostname[DHCP_HOSTNAME_MAX - 1] = '\0';
            }
            return;
        }
    }

    /* Find a free or expired slot */
    int slot = -1;
    int64_t oldest_exp = INT64_MAX;
    int oldest_slot = 0;
    for (int i = 0; i < DHCP_LEASE_MAP_SIZE; i++) {
        dhcp_lease_entry_t *e = &s_map[i];
        if (!e->valid || e->expires_us <= now) {
            if (slot < 0) slot = i;
        }
        if (e->expires_us < oldest_exp) {
            oldest_exp = e->expires_us;
            oldest_slot = i;
        }
    }
    if (slot < 0) slot = oldest_slot;

    dhcp_lease_entry_t *e = &s_map[slot];
    memcpy(e->mac, mac, 6);
    e->ip = ip;
    e->expires_us = expires;
    e->hostname[0] = '\0';
    if (hostname && hostname[0]) {
        strncpy(e->hostname, hostname, DHCP_HOSTNAME_MAX - 1);
        e->hostname[DHCP_HOSTNAME_MAX - 1] = '\0';
    }
    e->valid = true;
    ESP_LOGI(TAG, "learned mac=%02x:%02x:%02x:%02x:%02x:%02x ip=%08" PRIx32 " host=%s",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ip,
             e->hostname[0] ? e->hostname : "(none)");
}

bool dhcp_lease_map_lookup(const uint8_t mac[6], uint32_t *ip_out,
                           char *hostname_out, size_t hostname_max) {
    int64_t now = esp_timer_get_time();
    for (int i = 0; i < DHCP_LEASE_MAP_SIZE; i++) {
        dhcp_lease_entry_t *e = &s_map[i];
        if (!e->valid || e->expires_us <= now) continue;
        if (memcmp(e->mac, mac, 6) != 0) continue;
        if (ip_out) *ip_out = e->ip;
        if (hostname_out && hostname_max > 0) {
            strncpy(hostname_out, e->hostname, hostname_max - 1);
            hostname_out[hostname_max - 1] = '\0';
        }
        return true;
    }
    return false;
}

bool dhcp_lease_map_lookup_by_hostname(const char *hostname, uint32_t *ip_out) {
    if (!hostname || !hostname[0]) return false;
    int64_t now = esp_timer_get_time();
    for (int i = 0; i < DHCP_LEASE_MAP_SIZE; i++) {
        dhcp_lease_entry_t *e = &s_map[i];
        if (!e->valid || e->expires_us <= now) continue;
        if (e->ip == 0 || e->hostname[0] == '\0') continue;
        if (strcasecmp(e->hostname, hostname) == 0) {
            if (ip_out) *ip_out = e->ip;
            return true;
        }
    }
    return false;
}

void dhcp_lease_map_set_hostname(const uint8_t mac[6], const char *hostname) {
    if (!hostname || !hostname[0]) return;
    int64_t now = esp_timer_get_time();

    /* Update hostname in existing entry without touching IP or TTL */
    for (int i = 0; i < DHCP_LEASE_MAP_SIZE; i++) {
        dhcp_lease_entry_t *e = &s_map[i];
        if (e->valid && memcmp(e->mac, mac, 6) == 0) {
            strncpy(e->hostname, hostname, DHCP_HOSTNAME_MAX - 1);
            e->hostname[DHCP_HOSTNAME_MAX - 1] = '\0';
            return;
        }
    }

    /* No existing entry — create a placeholder with ip=0 and short TTL so the
     * hostname is ready when the DHCPACK arrives and updates the IP. */
    int slot = -1;
    int64_t oldest_exp = INT64_MAX;
    int oldest_slot = 0;
    for (int i = 0; i < DHCP_LEASE_MAP_SIZE; i++) {
        dhcp_lease_entry_t *e = &s_map[i];
        if (!e->valid || e->expires_us <= now) {
            if (slot < 0) slot = i;
        }
        if (e->expires_us < oldest_exp) {
            oldest_exp = e->expires_us;
            oldest_slot = i;
        }
    }
    if (slot < 0) slot = oldest_slot;

    dhcp_lease_entry_t *e = &s_map[slot];
    memcpy(e->mac, mac, 6);
    e->ip = 0;
    e->expires_us = now + 120LL * 1000000LL; /* 2 min placeholder TTL */
    strncpy(e->hostname, hostname, DHCP_HOSTNAME_MAX - 1);
    e->hostname[DHCP_HOSTNAME_MAX - 1] = '\0';
    e->valid = true;
}

int dhcp_lease_map_snapshot(dhcp_lease_entry_t *out, int max) {
    int64_t now = esp_timer_get_time();
    int n = 0;
    for (int i = 0; i < DHCP_LEASE_MAP_SIZE && n < max; i++) {
        dhcp_lease_entry_t *e = &s_map[i];
        if (!e->valid || e->expires_us <= now) continue;
        out[n] = *e;
        n++;
    }
    return n;
}

#endif
