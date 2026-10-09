/* Bandwidth Manager - Per-client rate limiting and daily usage tracking.
 *
 * Architecture:
 *   - Token-bucket rate limiting in the lwIP netif hot path (IRAM-safe)
 *   - Daily byte counters with automatic midnight reset via SNTP
 *   - NVS persistence for limits and accumulated usage
 *   - Background FreeRTOS task for daily reset and periodic NVS flush
 *
 * Thread safety: a single FreeRTOS mutex protects s_clients[].
 * The hot-path check (bw_check_*) uses a non-blocking take with a
 * 1-tick timeout so the lwIP task is never stalled.
 *
 * SPDX-License-Identifier: MIT
 */

#include <string.h>
#include <time.h>
#include "esp_log.h"
#include "esp_timer.h"
#include "nvs.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "bandwidth_manager.h"

static const char *TAG = "bw_mgr";

#define BW_NVS_NS   "esp32_nat"
#define BW_NVS_KEY  "bw_data"

/* NVS save at most every 5 minutes */
#define BW_SAVE_INTERVAL_US  (5LL * 60 * 1000000)

/* Background task period */
#define BW_TASK_PERIOD_MS    60000  /* 60 seconds */

/* ── static state ─────────────────────────────────────────────── */

static client_bw_entry_t s_clients[BW_MAX_CLIENTS];
static SemaphoreHandle_t s_mutex;
static int64_t s_last_save_us;

/* ── token bucket helpers (IRAM for hot path) ─────────────────── */

static void tb_init(bw_token_bucket_t *b, uint32_t rate_bps)
{
    b->rate_bps    = rate_bps;
    b->burst_bytes = rate_bps * 2;          /* allow 2× burst */
    if (b->burst_bytes < 4096 && rate_bps > 0)
        b->burst_bytes = 4096;
    b->tokens        = (int32_t)b->burst_bytes; /* start full */
    b->last_refill_us = esp_timer_get_time();
}

static IRAM_ATTR void tb_refill(bw_token_bucket_t *b)
{
    if (b->rate_bps == 0) return;

    int64_t now = esp_timer_get_time();
    int64_t elapsed = now - b->last_refill_us;
    if (elapsed <= 0) return;

    /* new_tokens = elapsed_us * rate_bps / 1 000 000 */
    int64_t add = (elapsed * (int64_t)b->rate_bps) / 1000000;
    b->tokens += (int32_t)add;
    if (b->tokens > (int32_t)b->burst_bytes)
        b->tokens = (int32_t)b->burst_bytes;
    b->last_refill_us = now;
}

static IRAM_ATTR bool tb_consume(bw_token_bucket_t *b, uint32_t bytes)
{
    if (b->rate_bps == 0) return true;      /* unlimited */

    tb_refill(b);

    if (b->tokens >= (int32_t)bytes) {
        b->tokens -= (int32_t)bytes;
        return true;
    }
    return false;                           /* rate-limited */
}

/* ── client lookup ────────────────────────────────────────────── */

static client_bw_entry_t *find_client(const uint8_t *mac)
{
    for (int i = 0; i < BW_MAX_CLIENTS; i++)
        if (s_clients[i].active && memcmp(s_clients[i].mac, mac, 6) == 0)
            return &s_clients[i];
    return NULL;
}

static client_bw_entry_t *find_or_create(const uint8_t *mac)
{
    client_bw_entry_t *e = find_client(mac);
    if (e) return e;

    for (int i = 0; i < BW_MAX_CLIENTS; i++) {
        if (!s_clients[i].active) {
            memset(&s_clients[i], 0, sizeof(s_clients[i]));
            memcpy(s_clients[i].mac, mac, 6);
            s_clients[i].active = true;
            return &s_clients[i];
        }
    }
    return NULL;    /* table full */
}

/* ── NVS helpers ──────────────────────────────────────────────── */

static void nvs_load(void)
{
    nvs_handle_t h;
    if (nvs_open(BW_NVS_NS, NVS_READONLY, &h) != ESP_OK) return;
    size_t len = sizeof(s_clients);
    if (nvs_get_blob(h, BW_NVS_KEY, s_clients, &len) != ESP_OK)
        memset(s_clients, 0, sizeof(s_clients));
    nvs_close(h);
}

static void nvs_save(void)
{
    nvs_handle_t h;
    if (nvs_open(BW_NVS_NS, NVS_READWRITE, &h) != ESP_OK) return;
    nvs_set_blob(h, BW_NVS_KEY, s_clients, sizeof(s_clients));
    nvs_commit(h);
    nvs_close(h);
}

/* ── daily reset ──────────────────────────────────────────────── */

static void check_daily_reset(void)
{
    time_t now;
    time(&now);
    if (now < 100000) return;               /* SNTP not yet synced */

    struct tm ti;
    localtime_r(&now, &ti);
    uint32_t today = ti.tm_yday;

    bool changed = false;
    for (int i = 0; i < BW_MAX_CLIENTS; i++) {
        if (s_clients[i].active && s_clients[i].last_reset_day != today) {
            /* Carry over unused quota to next day */
            if (s_clients[i].daily_cap_bytes > 0) {
                uint64_t used = s_clients[i].daily_up_bytes + s_clients[i].daily_down_bytes;
                if (used < s_clients[i].daily_cap_bytes) {
                    s_clients[i].daily_rollover_bytes += s_clients[i].daily_cap_bytes - used;
                    /* Cap rollover at 1× daily cap (max 2 days total) */
                    if (s_clients[i].daily_rollover_bytes > s_clients[i].daily_cap_bytes)
                        s_clients[i].daily_rollover_bytes = s_clients[i].daily_cap_bytes;
                }
            }

            ESP_LOGI(TAG, "Daily reset for %02X:%02X:%02X:%02X:%02X:%02X "
                     "(up %"PRIu64" B, down %"PRIu64" B, rollover %"PRIu64" B)",
                     s_clients[i].mac[0], s_clients[i].mac[1],
                     s_clients[i].mac[2], s_clients[i].mac[3],
                     s_clients[i].mac[4], s_clients[i].mac[5],
                     s_clients[i].daily_up_bytes, s_clients[i].daily_down_bytes,
                     s_clients[i].daily_rollover_bytes);
            s_clients[i].daily_up_bytes   = 0;
            s_clients[i].daily_down_bytes = 0;
            s_clients[i].blocked          = false;
            s_clients[i].last_reset_day   = today;
            changed = true;
        }
    }
    if (changed) nvs_save();
}

/* ── background task ──────────────────────────────────────────── */

static void bw_task(void *arg)
{
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(BW_TASK_PERIOD_MS));

        xSemaphoreTake(s_mutex, portMAX_DELAY);
        check_daily_reset();

        /* Periodic NVS flush */
        int64_t now = esp_timer_get_time();
        if (now - s_last_save_us >= BW_SAVE_INTERVAL_US) {
            nvs_save();
            s_last_save_us = now;
        }
        xSemaphoreGive(s_mutex);
    }
}

/* ── public API ───────────────────────────────────────────────── */

void bw_init(void)
{
    s_mutex = xSemaphoreCreateMutex();
    memset(s_clients, 0, sizeof(s_clients));
    s_last_save_us = esp_timer_get_time();

    nvs_load();

    /* Apply daily reset if needed on boot */
    check_daily_reset();

    xTaskCreate(bw_task, "bw_task", 3072, NULL, 1, NULL);
    ESP_LOGI(TAG, "Bandwidth manager initialised (%d slots)", BW_MAX_CLIENTS);
}

esp_err_t bw_set_limits(const uint8_t *mac,
                        uint32_t upload_bps,
                        uint32_t download_bps,
                        uint64_t daily_cap_bytes)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);

    client_bw_entry_t *e = find_or_create(mac);
    if (!e) {
        xSemaphoreGive(s_mutex);
        return ESP_ERR_NO_MEM;
    }

    e->upload_bps      = upload_bps;
    e->download_bps    = download_bps;
    e->daily_cap_bytes = daily_cap_bytes;

    tb_init(&e->up_bucket,   upload_bps);
    tb_init(&e->down_bucket, download_bps);

    nvs_save();
    xSemaphoreGive(s_mutex);

    ESP_LOGI(TAG, "Limits for %02X:%02X:%02X:%02X:%02X:%02X: "
             "up %"PRIu32" B/s, down %"PRIu32" B/s, cap %"PRIu64" B",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
             upload_bps, download_bps, daily_cap_bytes);
    return ESP_OK;
}

esp_err_t bw_remove(const uint8_t *mac)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    client_bw_entry_t *e = find_client(mac);
    if (e) e->active = false;
    nvs_save();
    xSemaphoreGive(s_mutex);
    return ESP_OK;
}

void bw_clear_all(void)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    memset(s_clients, 0, sizeof(s_clients));
    nvs_save();
    xSemaphoreGive(s_mutex);
    ESP_LOGI(TAG, "All bandwidth entries cleared");
}

/* Hot-path check: upload (client -> Internet).
 * Called from ap_netif_input_hook with the source MAC. */
bool bw_check_upload(const uint8_t *mac, uint32_t bytes)
{
    if (!s_mutex) return true;

    /* Non-blocking take: if mutex is held, allow packet through */
    if (xSemaphoreTake(s_mutex, 1) != pdTRUE)
        return true;

    client_bw_entry_t *e = find_client(mac);
    if (!e) { xSemaphoreGive(s_mutex); return true; }

    /* Already blocked by daily cap? */
    if (e->blocked) { xSemaphoreGive(s_mutex); return false; }

    /* Daily cap check (base cap + rolled-over unused quota) */
    if (e->daily_cap_bytes > 0) {
        uint64_t effective_cap = e->daily_cap_bytes + e->daily_rollover_bytes;
        e->daily_up_bytes += bytes;
        e->total_up_bytes += bytes;
        if (e->daily_up_bytes + e->daily_down_bytes > effective_cap) {
            e->blocked = true;
            ESP_LOGW(TAG, "Client %02X:%02X:%02X:%02X:%02X:%02X hit daily cap "
                     "(up %"PRIu64" + down %"PRIu64" > %"PRIu64")",
                     mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                     e->daily_up_bytes, e->daily_down_bytes,
                     effective_cap);
            xSemaphoreGive(s_mutex);
            return false;
        }
    } else {
        e->total_up_bytes += bytes;
    }

    /* Token-bucket rate limit */
    if (!tb_consume(&e->up_bucket, bytes)) {
        xSemaphoreGive(s_mutex);
        return false;
    }

    xSemaphoreGive(s_mutex);
    return true;
}

/* Hot-path check: download (Internet -> client).
 * Called from ap_netif_linkoutput_hook with the destination MAC. */
bool bw_check_download(const uint8_t *mac, uint32_t bytes)
{
    if (!s_mutex) return true;

    if (xSemaphoreTake(s_mutex, 1) != pdTRUE)
        return true;

    client_bw_entry_t *e = find_client(mac);
    if (!e) { xSemaphoreGive(s_mutex); return true; }

    if (e->blocked) { xSemaphoreGive(s_mutex); return false; }

    if (e->daily_cap_bytes > 0) {
        uint64_t effective_cap = e->daily_cap_bytes + e->daily_rollover_bytes;
        e->daily_down_bytes += bytes;
        e->total_down_bytes += bytes;
        if (e->daily_up_bytes + e->daily_down_bytes > effective_cap) {
            e->blocked = true;
            ESP_LOGW(TAG, "Client %02X:%02X:%02X:%02X:%02X:%02X hit daily cap "
                     "(up %"PRIu64" + down %"PRIu64" > %"PRIu64")",
                     mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                     e->daily_up_bytes, e->daily_down_bytes,
                     effective_cap);
            xSemaphoreGive(s_mutex);
            return false;
        }
    } else {
        e->total_down_bytes += bytes;
    }

    if (!tb_consume(&e->down_bucket, bytes)) {
        xSemaphoreGive(s_mutex);
        return false;
    }

    xSemaphoreGive(s_mutex);
    return true;
}

client_bw_entry_t *bw_get_all(void)
{
    return s_clients;
}

void bw_save_to_nvs(void)
{
    if (!s_mutex) return;
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    nvs_save();
    xSemaphoreGive(s_mutex);
}
