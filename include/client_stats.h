/* Per-client traffic statistics for AP-connected clients.
 *
 * SPDX-License-Identifier: MIT
 */
#pragma once

#include <stdint.h>
#include <string.h>
#include "router_config.h"

#define CLIENT_STATS_MAX AP_MAX_CONNECTIONS

typedef struct {
    uint8_t  mac[6];
    uint8_t  active;           /* 1 = slot in use (has stats) */
    uint8_t  connected;        /* 1 = currently connected to AP */
    uint64_t bytes_sent;       /* bytes sent TO this client (linkoutput) */
    uint64_t bytes_received;   /* bytes received FROM this client (input) */
    uint32_t packets_sent;
    uint32_t packets_received;
} client_stats_entry_t;

/* Called from WiFi event handlers on client connect/disconnect */
void client_stats_on_connect(const uint8_t *mac);
void client_stats_on_disconnect(const uint8_t *mac);

/* Copy active entries into caller-provided buffer. Returns count copied. */
int client_stats_get_all(client_stats_entry_t *out, int max_entries);

/* Zero all counters but keep active/mac state */
void client_stats_reset_all(void);

/* Format byte count as human-readable string (e.g. "1.2 MB") */
void format_bytes_human(uint64_t bytes, char *buf, size_t len);
