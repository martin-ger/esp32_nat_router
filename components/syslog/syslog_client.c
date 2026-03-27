/* Syslog client - forward ESP logs to a remote syslog server via UDP
 *
 * Uses esp_log_set_vprintf() to intercept all ESP_LOG output,
 * formats as RFC 3164 BSD syslog, and sends via UDP.
 * Serial console output is always preserved.
 *
 * Architecture:
 *   vprintf hook  ──format──>  FreeRTOS queue  ──sendto──>  UDP socket
 *
 * The vprintf hook never touches lwIP (no sendto, no DNS). It formats
 * the syslog packet into a heap buffer and posts it to a queue.
 * A dedicated sender task dequeues packets and calls sendto().
 * This avoids deadlocks when logging from lwIP/event contexts.
 *
 * All buffers and the sender task are created on enable, destroyed
 * on disable — zero RAM when syslog is not active.
 *
 * SPDX-License-Identifier: MIT
 */

#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdatomic.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>

#include "esp_log.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "lwip/sockets.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/queue.h"
#include "freertos/task.h"

#include "syslog_client.h"
#include "router_config.h"
#include "wifi_config.h"

static const char *TAG = "syslog";

/* NVS keys */
#define NVS_KEY_ENABLED     "syslog_en"
#define NVS_KEY_SERVER      "syslog_srv"
#define NVS_KEY_PORT        "syslog_port"

/* Syslog facility: LOCAL0 (16) */
#define SYSLOG_FACILITY     16

/* Syslog severities */
#define SYSLOG_SEV_ERR      3
#define SYSLOG_SEV_WARNING  4
#define SYSLOG_SEV_NOTICE   5
#define SYSLOG_SEV_INFO     6
#define SYSLOG_SEV_DEBUG    7

/* Max syslog packet size */
#define SYSLOG_PKT_MAX      256

/* Queue depth — how many messages can be buffered */
#define SYSLOG_QUEUE_DEPTH  16

/* Message passed through the queue */
typedef struct {
    uint16_t len;
    char data[SYSLOG_PKT_MAX];
} syslog_msg_t;

/* Config state — protected by s_mutex */
static SemaphoreHandle_t s_mutex = NULL;
static atomic_bool s_enabled = false;
static char s_server[SYSLOG_MAX_SERVER_LEN] = {0};
static uint16_t s_port = SYSLOG_DEFAULT_PORT;

/* Sender task state */
static QueueHandle_t s_queue = NULL;
static TaskHandle_t s_sender_task = NULL;
static int s_sock = -1;
static struct sockaddr_in s_dest_addr;
static atomic_bool s_resolved = false;

/* Formatting state — protected by s_fmt_mutex (non-blocking trylock).
 * s_rawbuf accumulates partial log lines (WiFi driver splits lines
 * across multiple vprintf calls). Flushed when a newline is seen. */
static SemaphoreHandle_t s_fmt_mutex = NULL;
static char *s_rawbuf = NULL;   /* line accumulation buffer */
static char *s_pktbuf = NULL;   /* cleaned text for packet building */
static int s_rawpos = 0;        /* current write position in s_rawbuf */

static vprintf_like_t s_original_vprintf = NULL;

/* Per-task re-entrancy guard */
static _Thread_local bool tl_in_syslog = false;

/* ---- NVS helpers ---- */

static void load_config(void)
{
    nvs_handle_t nvs;
    if (nvs_open(PARAM_NAMESPACE, NVS_READONLY, &nvs) != ESP_OK)
        return;

    uint8_t en = 0;
    nvs_get_u8(nvs, NVS_KEY_ENABLED, &en);
    atomic_store(&s_enabled, en != 0);

    size_t len = sizeof(s_server);
    nvs_get_str(nvs, NVS_KEY_SERVER, s_server, &len);

    nvs_get_u16(nvs, NVS_KEY_PORT, &s_port);

    nvs_close(nvs);
}

static esp_err_t save_config(void)
{
    nvs_handle_t nvs;
    esp_err_t err = nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) return err;

    nvs_set_u8(nvs, NVS_KEY_ENABLED, atomic_load(&s_enabled) ? 1 : 0);
    nvs_set_str(nvs, NVS_KEY_SERVER, s_server);
    nvs_set_u16(nvs, NVS_KEY_PORT, s_port);
    err = nvs_commit(nvs);
    nvs_close(nvs);
    return err;
}

/* ---- Log level mapping ---- */

static int esp_level_to_syslog(char level_char)
{
    switch (level_char) {
        case 'E': return SYSLOG_SEV_ERR;
        case 'W': return SYSLOG_SEV_WARNING;
        case 'I': return SYSLOG_SEV_INFO;
        case 'D': return SYSLOG_SEV_DEBUG;
        case 'V': return SYSLOG_SEV_DEBUG;
        default:  return SYSLOG_SEV_NOTICE;
    }
}

static char extract_level_and_clean(const char *msg, const char **clean_start)
{
    const char *p = msg;
    char level = 'I';

    if (p[0] == '\033' && p[1] == '[') {
        p += 2;
        while (*p && *p != 'm') p++;
        if (*p == 'm') p++;
    }

    if (*p && (p[1] == ' ' || p[1] == '(')) {
        level = *p;
    }

    *clean_start = p;
    return level;
}

static int strip_ansi(const char *src, char *dst, int max_len)
{
    int j = 0;
    for (int i = 0; src[i] && j < max_len - 1; ) {
        if (src[i] == '\033') {
            i++;
            if (src[i] == '[') {
                i++;
                while (src[i] && src[i] != 'm') i++;
                if (src[i] == 'm') i++;
            }
        } else {
            dst[j++] = src[i++];
        }
    }
    while (j > 0 && (dst[j-1] == '\n' || dst[j-1] == '\r'))
        j--;
    dst[j] = '\0';
    return j;
}

/* ---- Sender task (owns the socket, does all lwIP calls) ---- */

static void sender_task(void *arg)
{
    syslog_msg_t msg;

    while (true) {
        if (xQueueReceive(s_queue, &msg, portMAX_DELAY) == pdTRUE) {
            if (msg.len == 0) {
                /* Poison pill — shut down */
                break;
            }
            if (s_sock >= 0 && atomic_load(&s_resolved)) {
                sendto(s_sock, msg.data, msg.len, 0,
                       (struct sockaddr *)&s_dest_addr, sizeof(s_dest_addr));
            }
        }
    }

    /* Clean up socket */
    if (s_sock >= 0) {
        close(s_sock);
        s_sock = -1;
    }
    atomic_store(&s_resolved, false);
    s_sender_task = NULL;
    vTaskDelete(NULL);
}

/* ---- vprintf hook (never touches lwIP) ---- */

static int syslog_vprintf(const char *fmt, va_list args)
{
    va_list args_copy;
    va_copy(args_copy, args);
    int ret = s_original_vprintf(fmt, args);

    /* Fast exit: disabled, no connectivity, re-entrant, or no queue */
    if (!atomic_load(&s_enabled) || !ap_connect || tl_in_syslog || !s_queue) {
        va_end(args_copy);
        return ret;
    }
    tl_in_syslog = true;

    /* Try to acquire format mutex — non-blocking.
     * If another task is formatting, drop this message. */
    if (xSemaphoreTake(s_fmt_mutex, 0) == pdTRUE) {
        if (s_rawbuf && s_pktbuf && atomic_load(&s_resolved)) {
            /* Append formatted text to accumulation buffer */
            int space = SYSLOG_PKT_MAX - s_rawpos - 1;
            if (space > 0) {
                int n = vsnprintf(s_rawbuf + s_rawpos, space + 1, fmt, args_copy);
                if (n > 0) {
                    s_rawpos += (n > space) ? space : n;
                }
            }

            /* Check if the accumulated text contains a newline (line complete) */
            bool has_newline = (s_rawpos > 0 && memchr(s_rawbuf, '\n', s_rawpos));

            if (has_newline) {
                /* Extract level, strip ANSI from accumulated line */
                s_rawbuf[s_rawpos] = '\0';
                const char *clean_start;
                char level_char = extract_level_and_clean(s_rawbuf, &clean_start);
                int clean_len = strip_ansi(clean_start, s_pktbuf, SYSLOG_PKT_MAX);

                /* Reset accumulation buffer for next line */
                s_rawpos = 0;

                /* Skip stub lines like "I (12345) wifi:" with no real content.
                 * WiFi driver splits output across multiple vprintf calls;
                 * the first call is just the tag, the second has the content. */
                const char *colon = strrchr(s_pktbuf, ':');
                bool is_stub = false;
                if (colon) {
                    /* Check if everything after the last colon is whitespace */
                    const char *p = colon + 1;
                    while (*p == ' ') p++;
                    if (*p == '\0') is_stub = true;
                }

                if (clean_len > 0 && !is_stub) {
                    char timestamp[20];
                    time_t now = time(NULL);
                    struct tm tm_info;
                    localtime_r(&now, &tm_info);
                    if (now > 1000000000) {
                        strftime(timestamp, sizeof(timestamp), "%b %e %H:%M:%S", &tm_info);
                    } else {
                        snprintf(timestamp, sizeof(timestamp), "Jan  1 00:00:00");
                    }

                    const char *host = hostname;
                    int severity = esp_level_to_syslog(level_char);
                    int priority = SYSLOG_FACILITY * 8 + severity;

                    syslog_msg_t msg;
                    int pkt_len = snprintf(msg.data, sizeof(msg.data), "<%d>%s %s %s\n",
                                           priority, timestamp, host, s_pktbuf);
                    if (pkt_len > 0) {
                        if (pkt_len > (int)sizeof(msg.data))
                            pkt_len = sizeof(msg.data);
                        msg.len = (uint16_t)pkt_len;
                        xQueueSend(s_queue, &msg, 0);
                    }
                }
            }
        }
        xSemaphoreGive(s_fmt_mutex);
    }

    va_end(args_copy);
    tl_in_syslog = false;
    return ret;
}

/* ---- Resource management ---- */

static void start_sender(void)
{
    if (!s_queue) {
        s_queue = xQueueCreate(SYSLOG_QUEUE_DEPTH, sizeof(syslog_msg_t));
    }
    if (!s_fmt_mutex) {
        s_fmt_mutex = xSemaphoreCreateMutex();
    }
    if (!s_rawbuf) { s_rawbuf = malloc(SYSLOG_PKT_MAX); s_rawpos = 0; }
    if (!s_pktbuf) s_pktbuf = malloc(SYSLOG_PKT_MAX);

    if (!s_sender_task && s_queue) {
        xTaskCreate(sender_task, "syslog_tx", 3072, NULL, 5, &s_sender_task);
    }
}

static void stop_sender(void)
{
    if (s_queue && s_sender_task) {
        /* Send poison pill to stop the sender task */
        syslog_msg_t msg = { .len = 0 };
        xQueueSend(s_queue, &msg, pdMS_TO_TICKS(100));
        /* Give the task time to exit */
        vTaskDelay(pdMS_TO_TICKS(50));
    }
    if (s_queue) {
        vQueueDelete(s_queue);
        s_queue = NULL;
    }
    free(s_rawbuf); s_rawbuf = NULL;
    free(s_pktbuf); s_pktbuf = NULL;
}

/* Resolve DNS and open socket. Call from a normal task context. */
static void syslog_connect(void)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    if (!atomic_load(&s_enabled) || s_server[0] == '\0') {
        xSemaphoreGive(s_mutex);
        return;
    }

    /* Close old socket if any */
    if (s_sock >= 0) {
        close(s_sock);
        s_sock = -1;
    }
    atomic_store(&s_resolved, false);

    /* DNS resolution (blocking — that's fine, we're in a worker task) */
    struct addrinfo hints = {
        .ai_family = AF_INET,
        .ai_socktype = SOCK_DGRAM,
    };
    struct addrinfo *res = NULL;
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", s_port);

    /* Release mutex during DNS (it can take a while) */
    char server_copy[SYSLOG_MAX_SERVER_LEN];
    strncpy(server_copy, s_server, sizeof(server_copy));
    server_copy[sizeof(server_copy) - 1] = '\0';
    xSemaphoreGive(s_mutex);

    int ret = getaddrinfo(server_copy, port_str, &hints, &res);

    xSemaphoreTake(s_mutex, portMAX_DELAY);
    if (ret == 0 && res != NULL) {
        memcpy(&s_dest_addr, res->ai_addr, sizeof(s_dest_addr));
        freeaddrinfo(res);

        /* Open UDP socket */
        s_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (s_sock >= 0) {
            atomic_store(&s_resolved, true);
        }
    } else {
        if (res) freeaddrinfo(res);
    }

    /* Start sender task and buffers */
    start_sender();
    xSemaphoreGive(s_mutex);
}

/* ---- Public API ---- */

esp_err_t syslog_init(void)
{
    s_mutex = xSemaphoreCreateMutex();
    if (!s_mutex) return ESP_ERR_NO_MEM;

    load_config();

    /* Always install the hook so we can enable/disable at runtime */
    s_original_vprintf = esp_log_set_vprintf(syslog_vprintf);

    if (atomic_load(&s_enabled) && s_server[0] != '\0') {
        ESP_LOGI(TAG, "Syslog enabled: %s:%u", s_server, s_port);
        syslog_connect();
    }

    return ESP_OK;
}

esp_err_t syslog_enable(const char *server, uint16_t port)
{
    if (!server || server[0] == '\0')
        return ESP_ERR_INVALID_ARG;

    xSemaphoreTake(s_mutex, portMAX_DELAY);
    strncpy(s_server, server, sizeof(s_server) - 1);
    s_server[sizeof(s_server) - 1] = '\0';
    s_port = port;
    atomic_store(&s_enabled, true);
    atomic_store(&s_resolved, false);
    xSemaphoreGive(s_mutex);

    syslog_connect();

    esp_err_t err = save_config();
    if (err != ESP_OK) return err;

    ESP_LOGI(TAG, "Syslog enabled: %s:%u", s_server, s_port);
    return ESP_OK;
}

esp_err_t syslog_disable(void)
{
    atomic_store(&s_enabled, false);

    xSemaphoreTake(s_mutex, portMAX_DELAY);
    stop_sender();
    if (s_sock >= 0) {
        close(s_sock);
        s_sock = -1;
    }
    atomic_store(&s_resolved, false);
    xSemaphoreGive(s_mutex);

    save_config();
    ESP_LOGI(TAG, "Syslog disabled");
    return ESP_OK;
}

bool syslog_is_enabled(void)
{
    return atomic_load(&s_enabled);
}

void syslog_get_config(bool *enabled, char *server, size_t server_len, uint16_t *port)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);

    if (enabled) *enabled = atomic_load(&s_enabled);
    if (server && server_len > 0) {
        strncpy(server, s_server, server_len - 1);
        server[server_len - 1] = '\0';
    }
    if (port) *port = s_port;

    xSemaphoreGive(s_mutex);
}

static void syslog_connect_task(void *arg)
{
    syslog_connect();
    vTaskDelete(NULL);
}

void syslog_notify_connected(void)
{
    if (atomic_load(&s_enabled) && !atomic_load(&s_resolved)) {
        xTaskCreate(syslog_connect_task, "syslog_dns", 3072, NULL, 5, NULL);
    }
}
