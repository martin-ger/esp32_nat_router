#pragma once

#include "sdkconfig.h"

#if CONFIG_REPEATER_MODE

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "dhcp_helpers.h"

#define DHCP_LEASE_MAP_SIZE 16

typedef struct {
    uint8_t  mac[6];
    uint32_t ip;                        /* network byte order */
    char     hostname[DHCP_HOSTNAME_MAX];
    int64_t  expires_us;
    bool     valid;
} dhcp_lease_entry_t;

void dhcp_lease_map_init(void);

/* Upsert a lease entry; lease_sec=0 uses a default TTL. */
void dhcp_lease_map_update(const uint8_t mac[6], uint32_t ip,
                           const char *hostname, uint32_t lease_sec);

/* Store hostname learned from a client DHCP request (before ACK is seen).
 * Does not overwrite an existing valid IP. */
void dhcp_lease_map_set_hostname(const uint8_t mac[6], const char *hostname);

/* Look up by MAC; returns true if a non-expired entry was found. */
bool dhcp_lease_map_lookup(const uint8_t mac[6], uint32_t *ip_out,
                           char *hostname_out, size_t hostname_max);

/* Look up by hostname (case-insensitive); returns true if found with ip != 0. */
bool dhcp_lease_map_lookup_by_hostname(const char *hostname, uint32_t *ip_out);

/* Fill out[] with up to max non-expired entries; returns count written. */
int dhcp_lease_map_snapshot(dhcp_lease_entry_t *out, int max);

#endif
