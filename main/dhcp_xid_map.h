#pragma once

#include "sdkconfig.h"

#if CONFIG_REPEATER_MODE

#include <stdint.h>
#include <stdbool.h>

void dhcp_xid_map_init(void);
void dhcp_xid_map_insert(uint32_t xid, const uint8_t chaddr[6]);
bool dhcp_xid_map_lookup(uint32_t xid, uint8_t chaddr_out[6]);
void dhcp_xid_map_age(void);

typedef struct {
    uint32_t xid;
    uint8_t  chaddr[6];
    int32_t  ttl_remaining;
} dhcp_xid_snapshot_entry_t;
int dhcp_xid_map_snapshot(dhcp_xid_snapshot_entry_t *out, int max);

#endif
