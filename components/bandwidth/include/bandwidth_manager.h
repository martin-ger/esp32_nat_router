/* Bandwidth Manager - Per-client rate limiting and daily usage tracking.
 *
 * Uses a token-bucket algorithm for rate limiting and byte counters
 * for daily usage tracking.  Limits and usage are persisted to NVS
 * and a background task resets daily counters at midnight (SNTP).
 *
 * SPDX-License-Identifier: MIT
 */
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum clients tracked simultaneously */
#define BW_MAX_CLIENTS 8

/* Token bucket for byte-rate limiting */
typedef struct {
    uint32_t rate_bps;          /* Sustained rate in bytes/sec (0 = unlimited) */
    uint32_t burst_bytes;       /* Bucket capacity (max burst) */
    int32_t  tokens;            /* Current tokens (may go negative briefly) */
    int64_t  last_refill_us;    /* Timestamp of last refill (us, esp_timer) */
} bw_token_bucket_t;

/* Per-client bandwidth entry */
typedef struct {
    uint8_t  mac[6];            /* Client MAC */
    bool     active;            /* Slot in use */

    /* Configurable limits (0 = unlimited) */
    uint32_t upload_bps;        /* Upload rate limit, bytes/sec */
    uint32_t download_bps;      /* Download rate limit, bytes/sec */
    uint64_t daily_cap_bytes;   /* Daily total-data cap, bytes (up+down) */

    /* Token buckets (runtime) */
    bw_token_bucket_t up_bucket;
    bw_token_bucket_t down_bucket;

    /* Daily usage counters */
    uint64_t daily_up_bytes;    /* Bytes uploaded today */
    uint64_t daily_down_bytes;  /* Bytes downloaded today */
    uint64_t daily_rollover_bytes; /* Unused quota carried from previous days */
    uint32_t last_reset_day;    /* tm_yday when counters were last reset */

    /* Cumulative stats (since boot / last NVS save) */
    uint64_t total_up_bytes;
    uint64_t total_down_bytes;

    /* Runtime state */
    bool     blocked;           /* true when daily cap exceeded */
} client_bw_entry_t;

/**
 * Initialise the bandwidth subsystem.
 * Loads persisted data from NVS, starts the daily-reset background task.
 * Must be called once from app_main().
 */
void bw_init(void);

/**
 * Set (or update) bandwidth limits for a MAC address.
 * Persisted to NVS immediately.
 */
esp_err_t bw_set_limits(const uint8_t *mac,
                        uint32_t upload_bps,
                        uint32_t download_bps,
                        uint64_t daily_cap_bytes);

/**
 * Remove all bandwidth limits and usage for a MAC address.
 */
esp_err_t bw_remove(const uint8_t *mac);

/**
 * Remove all bandwidth entries.
 */
void bw_clear_all(void);

/**
 * Check an outbound (upload) packet from a client.
 * Returns true if the packet is allowed, false if it should be dropped.
 * Also increments daily upload counter when allowed.
 */
bool bw_check_upload(const uint8_t *mac, uint32_t bytes);

/**
 * Check an inbound (download) packet to a client.
 * Returns true if the packet is allowed, false if it should be dropped.
 * Also increments daily download counter when allowed.
 */
bool bw_check_download(const uint8_t *mac, uint32_t bytes);

/**
 * Return pointer to the static client array (for UI / CLI display).
 * Caller should treat the pointer as valid until the next bw_* call.
 */
client_bw_entry_t *bw_get_all(void);

/**
 * Force-save current state to NVS.
 */
void bw_save_to_nvs(void);

#ifdef __cplusplus
}
#endif
