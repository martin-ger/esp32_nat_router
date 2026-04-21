#pragma once

#include "sdkconfig.h"

#if CONFIG_REPEATER_MODE

#include <stdint.h>
#include <stdbool.h>

void fdb_init(void);
void fdb_learn(uint32_t ip, const uint8_t mac[6], uint32_t ttl_seconds);
bool fdb_lookup_by_ip(uint32_t ip, uint8_t mac_out[6]);
uint32_t fdb_lookup_by_mac(const uint8_t mac[6]);
void fdb_age(void);
void fdb_clear(void);

/* Snapshot entry for inspection/dump. */
typedef struct {
    uint32_t ip;            /* network byte order */
    uint8_t  mac[6];
    int32_t  ttl_remaining; /* seconds; negative if expired */
} fdb_snapshot_entry_t;

/* Fills out[] with up to max valid entries; returns count written. */
int fdb_snapshot(fdb_snapshot_entry_t *out, int max);

#endif
