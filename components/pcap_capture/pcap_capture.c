/* PCAP Capture - Capture AP interface traffic and stream via TCP

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_timer.h"

#include "pcap_capture.h"
#include "pcap_ringbuf.h"

static const char *TAG = "pcap_capture";

// Configuration
#define PCAP_TCP_PORT           19000
#define PCAP_TASK_STACK         3072
#define PCAP_TASK_PRIORITY      5
#if CONFIG_IDF_TARGET_ESP32C3
#define PCAP_RINGBUF_SIZE       (16 * 1024)  // 16KB ring buffer for ESP32-C3
#define PCAP_SNAPLEN_DEFAULT    64           // Default max packet capture size for ESP32-C3
#else
#define PCAP_RINGBUF_SIZE       (32 * 1024)  // 32KB ring buffer
#define PCAP_SNAPLEN_DEFAULT    96           // Default max packet capture size
#endif
#define PCAP_SNAPLEN_MAX        1600         // Maximum allowed snaplen (full Ethernet frame)
#define PCAP_SEND_BUF_SIZE      1024         // TCP send buffer size

// PCAP file format structures (little-endian)
typedef struct __attribute__((packed)) {
    uint32_t magic_number;   // 0xa1b2c3d4
    uint16_t version_major;  // 2
    uint16_t version_minor;  // 4
    int32_t  thiszone;       // GMT offset (0)
    uint32_t sigfigs;        // Timestamp accuracy (0)
    uint32_t snaplen;        // Max packet length
    uint32_t network;        // Link type (1 = Ethernet)
} pcap_global_header_t;

typedef struct __attribute__((packed)) {
    uint32_t ts_sec;         // Timestamp seconds
    uint32_t ts_usec;        // Timestamp microseconds
    uint32_t incl_len;       // Captured packet length
    uint32_t orig_len;       // Original packet length
} pcap_packet_header_t;

// State
static pcap_capture_mode_t capture_mode = PCAP_MODE_OFF;
static bool client_connected = false;
static int client_socket = -1;
static TaskHandle_t pcap_task_handle = NULL;
static uint32_t captured_packets = 0;
static uint16_t pcap_snaplen = PCAP_SNAPLEN_DEFAULT;

// Create PCAP global header
static void create_pcap_global_header(pcap_global_header_t *hdr)
{
    hdr->magic_number = 0xa1b2c3d4;  // Standard PCAP magic
    hdr->version_major = 2;
    hdr->version_minor = 4;
    hdr->thiszone = 0;               // UTC
    hdr->sigfigs = 0;
    hdr->snaplen = pcap_snaplen;
    hdr->network = 1;                // DLT_EN10MB (Ethernet)
}

// Send data to client socket with error handling
static bool send_to_client(int sock, const void *data, size_t len)
{
    const uint8_t *ptr = (const uint8_t *)data;
    size_t remaining = len;

    while (remaining > 0) {
        ssize_t sent = send(sock, ptr, remaining, 0);
        if (sent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                vTaskDelay(pdMS_TO_TICKS(10));
                continue;
            }
            ESP_LOGW(TAG, "Send failed: %s", strerror(errno));
            return false;
        }
        ptr += sent;
        remaining -= sent;
    }
    return true;
}

// TCP server task
static void pcap_server_task(void *arg)
{
    int listen_sock = -1;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    // Create listening socket
    listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock < 0) {
        ESP_LOGE(TAG, "Failed to create socket: %s", strerror(errno));
        vTaskDelete(NULL);
        return;
    }

    // Allow socket reuse
    int opt = 1;
    setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Bind to port
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(PCAP_TCP_PORT);

    if (bind(listen_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        ESP_LOGE(TAG, "Failed to bind socket: %s", strerror(errno));
        close(listen_sock);
        vTaskDelete(NULL);
        return;
    }

    // Listen for connections
    if (listen(listen_sock, 1) < 0) {
        ESP_LOGE(TAG, "Failed to listen: %s", strerror(errno));
        close(listen_sock);
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "PCAP server listening on port %d", PCAP_TCP_PORT);

    // Buffer for reading from ring buffer
    uint8_t *send_buf = malloc(PCAP_SEND_BUF_SIZE);
    if (send_buf == NULL) {
        ESP_LOGE(TAG, "Failed to allocate send buffer");
        close(listen_sock);
        vTaskDelete(NULL);
        return;
    }

    while (1) {
        // Wait for client connection
        ESP_LOGI(TAG, "Waiting for client connection...");
        client_socket = accept(listen_sock, (struct sockaddr *)&client_addr, &client_addr_len);
        if (client_socket < 0) {
            ESP_LOGW(TAG, "Accept failed: %s", strerror(errno));
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }

        ESP_LOGI(TAG, "Client connected from %s:%d",
                 inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        client_connected = true;

        // Clear ring buffer on new connection
        ringbuf_reset();

        // Send PCAP global header
        pcap_global_header_t global_hdr;
        create_pcap_global_header(&global_hdr);
        if (!send_to_client(client_socket, &global_hdr, sizeof(global_hdr))) {
            ESP_LOGW(TAG, "Failed to send PCAP header");
            goto client_disconnect;
        }

        ESP_LOGI(TAG, "PCAP header sent, streaming packets...");

        // Stream packets while connected and capture enabled
        while (client_connected) {
            // Read from ring buffer (blocking with timeout)
            size_t bytes_read = ringbuf_read(send_buf, PCAP_SEND_BUF_SIZE, pdMS_TO_TICKS(100));
            if (bytes_read == 0) {
                // Check if socket is still connected
                char test;
                int result = recv(client_socket, &test, 1, MSG_PEEK | MSG_DONTWAIT);
                if (result == 0 || (result < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
                    ESP_LOGI(TAG, "Client disconnected");
                    break;
                }
                continue;
            }

            // Send data to client
            if (!send_to_client(client_socket, send_buf, bytes_read)) {
                ESP_LOGW(TAG, "Failed to send data, client disconnected");
                break;
            }
        }

client_disconnect:
        client_connected = false;
        if (client_socket >= 0) {
            close(client_socket);
            client_socket = -1;
        }
        ESP_LOGI(TAG, "Client session ended");
    }

    // Cleanup (unreachable in normal operation)
    free(send_buf);
    close(listen_sock);
    vTaskDelete(NULL);
}

void pcap_init(void)
{
    // Initialize ring buffer
    if (!ringbuf_init(PCAP_RINGBUF_SIZE)) {
        ESP_LOGE(TAG, "Failed to initialize ring buffer");
        return;
    }

    ESP_LOGI(TAG, "Capture ring buffer size: %d", PCAP_RINGBUF_SIZE);

    // Create TCP server task
    BaseType_t ret = xTaskCreate(
        pcap_server_task,
        "pcap_server",
        PCAP_TASK_STACK,
        NULL,
        PCAP_TASK_PRIORITY,
        &pcap_task_handle
    );

    if (ret != pdPASS) {
        ESP_LOGE(TAG, "Failed to create PCAP server task");
        return;
    }

    ESP_LOGI(TAG, "PCAP capture initialized (snaplen=%d, buffer=%dKB)",
             pcap_snaplen, PCAP_RINGBUF_SIZE / 1024);
}

bool pcap_should_capture(bool is_acl_monitored, bool is_ap_interface)
{
    // Must have a client connected to capture anything
    if (!client_connected) {
        return false;
    }

    switch (capture_mode) {
        case PCAP_MODE_OFF:
            return false;
        case PCAP_MODE_ACL_MONITOR:
            // Capture ACL-monitored packets from any interface
            return is_acl_monitored;
        case PCAP_MODE_PROMISCUOUS:
            // Capture all AP traffic, but not STA traffic
            return is_ap_interface;
    }
    return false;
}

void pcap_capture_packet(struct pbuf *p)
{
    if (p == NULL || !client_connected) {
        return;
    }

    // Create packet header
    pcap_packet_header_t pkt_hdr;
    int64_t now_us = esp_timer_get_time();
    pkt_hdr.ts_sec = (uint32_t)(now_us / 1000000);
    pkt_hdr.ts_usec = (uint32_t)(now_us % 1000000);
    pkt_hdr.orig_len = p->tot_len;
    pkt_hdr.incl_len = (p->tot_len > pcap_snaplen) ? pcap_snaplen : p->tot_len;

    // Temporary buffer for packet data (header + payload)
    // Using stack allocation with max size for performance
    uint8_t pkt_buf[sizeof(pcap_packet_header_t) + PCAP_SNAPLEN_MAX];

    // Copy header
    memcpy(pkt_buf, &pkt_hdr, sizeof(pkt_hdr));

    // Copy packet data (handles pbuf chains)
    size_t copied = 0;
    struct pbuf *q = p;
    while (q != NULL && copied < pkt_hdr.incl_len) {
        size_t to_copy = q->len;
        if (copied + to_copy > pkt_hdr.incl_len) {
            to_copy = pkt_hdr.incl_len - copied;
        }
        memcpy(pkt_buf + sizeof(pkt_hdr) + copied, q->payload, to_copy);
        copied += to_copy;
        q = q->next;
    }

    // Write to ring buffer (non-blocking)
    size_t total_len = sizeof(pkt_hdr) + pkt_hdr.incl_len;
    if (ringbuf_write(pkt_buf, total_len)) {
        captured_packets++;
    }
}

void pcap_set_mode(pcap_capture_mode_t mode)
{
    pcap_capture_mode_t old_mode = capture_mode;
    capture_mode = mode;

    // Reset counters when enabling capture
    if (old_mode == PCAP_MODE_OFF && mode != PCAP_MODE_OFF) {
        captured_packets = 0;
        ringbuf_reset();
    }

    ESP_LOGI(TAG, "Capture mode set to: %s", pcap_mode_to_string(mode));
}

pcap_capture_mode_t pcap_get_mode(void)
{
    return capture_mode;
}

const char* pcap_mode_to_string(pcap_capture_mode_t mode)
{
    switch (mode) {
        case PCAP_MODE_OFF:          return "off";
        case PCAP_MODE_ACL_MONITOR:  return "acl-monitor";
        case PCAP_MODE_PROMISCUOUS:  return "promiscuous";
        default:                     return "unknown";
    }
}

// Legacy API - kept for backwards compatibility
void pcap_capture_start(void)
{
    pcap_set_mode(PCAP_MODE_PROMISCUOUS);
}

void pcap_capture_stop(void)
{
    pcap_set_mode(PCAP_MODE_OFF);
}

bool pcap_capture_enabled(void)
{
    return capture_mode != PCAP_MODE_OFF;
}

bool pcap_client_connected(void)
{
    return client_connected;
}

uint32_t pcap_get_captured_count(void)
{
    return captured_packets;
}

uint32_t pcap_get_dropped_count(void)
{
    return ringbuf_get_dropped_count();
}

void pcap_get_buffer_usage(size_t *used, size_t *total)
{
    if (used) {
        *used = ringbuf_available_bytes();
    }
    if (total) {
        *total = ringbuf_total_size();
    }
}

uint16_t pcap_get_snaplen(void)
{
    return pcap_snaplen;
}

bool pcap_set_snaplen(uint16_t snaplen)
{
    if (snaplen < 64 || snaplen > PCAP_SNAPLEN_MAX) {
        ESP_LOGW(TAG, "Snaplen must be between 64 and %d", PCAP_SNAPLEN_MAX);
        return false;
    }
    pcap_snaplen = snaplen;
    ESP_LOGI(TAG, "Snaplen set to %d bytes", pcap_snaplen);
    return true;
}
