/* PCAP Ring Buffer - Thread-safe circular buffer for packet capture

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_log.h"

// Internal header for ring buffer
#include "pcap_ringbuf.h"

static const char *TAG = "pcap_ringbuf";

// Ring buffer state
static uint8_t *ringbuf_data = NULL;
static size_t ringbuf_size = 0;
static size_t ringbuf_head = 0;      // Write position
static size_t ringbuf_tail = 0;      // Read position
static size_t ringbuf_available = 0; // Bytes available to read
static uint32_t dropped_packets = 0;
static SemaphoreHandle_t ringbuf_mutex = NULL;
static SemaphoreHandle_t data_ready_sem = NULL;

bool ringbuf_init(size_t size)
{
    if (ringbuf_data != NULL) {
        ESP_LOGW(TAG, "Ring buffer already initialized");
        return true;
    }

    ringbuf_data = malloc(size);
    if (ringbuf_data == NULL) {
        ESP_LOGE(TAG, "Failed to allocate ring buffer (%d bytes)", size);
        return false;
    }

    ringbuf_size = size;
    ringbuf_head = 0;
    ringbuf_tail = 0;
    ringbuf_available = 0;
    dropped_packets = 0;

    ringbuf_mutex = xSemaphoreCreateMutex();
    if (ringbuf_mutex == NULL) {
        ESP_LOGE(TAG, "Failed to create mutex");
        free(ringbuf_data);
        ringbuf_data = NULL;
        return false;
    }

    data_ready_sem = xSemaphoreCreateBinary();
    if (data_ready_sem == NULL) {
        ESP_LOGE(TAG, "Failed to create semaphore");
        vSemaphoreDelete(ringbuf_mutex);
        free(ringbuf_data);
        ringbuf_data = NULL;
        return false;
    }

    ESP_LOGI(TAG, "Ring buffer initialized (%d bytes)", size);
    return true;
}

void ringbuf_reset(void)
{
    if (ringbuf_mutex == NULL) {
        return;
    }

    xSemaphoreTake(ringbuf_mutex, portMAX_DELAY);
    ringbuf_head = 0;
    ringbuf_tail = 0;
    ringbuf_available = 0;
    dropped_packets = 0;
    xSemaphoreGive(ringbuf_mutex);
}

bool ringbuf_write(const uint8_t *data, size_t len)
{
    if (ringbuf_data == NULL || ringbuf_mutex == NULL) {
        return false;
    }

    // Non-blocking take for ISR/hook context
    if (xSemaphoreTake(ringbuf_mutex, 0) != pdTRUE) {
        // Mutex busy, drop packet
        dropped_packets++;
        return false;
    }

    size_t free_space = ringbuf_size - ringbuf_available;
    if (len > free_space) {
        // Not enough space, drop packet
        dropped_packets++;
        xSemaphoreGive(ringbuf_mutex);
        return false;
    }

    // Write data, handling wrap-around
    size_t first_chunk = ringbuf_size - ringbuf_head;
    if (first_chunk >= len) {
        // No wrap needed
        memcpy(ringbuf_data + ringbuf_head, data, len);
        ringbuf_head = (ringbuf_head + len) % ringbuf_size;
    } else {
        // Wrap around
        memcpy(ringbuf_data + ringbuf_head, data, first_chunk);
        memcpy(ringbuf_data, data + first_chunk, len - first_chunk);
        ringbuf_head = len - first_chunk;
    }

    ringbuf_available += len;
    xSemaphoreGive(ringbuf_mutex);

    // Signal data ready
    xSemaphoreGive(data_ready_sem);

    return true;
}

size_t ringbuf_read(uint8_t *data, size_t max_len, TickType_t timeout)
{
    if (ringbuf_data == NULL || ringbuf_mutex == NULL) {
        return 0;
    }

    // Wait for data to be available
    if (xSemaphoreTake(data_ready_sem, timeout) != pdTRUE) {
        return 0; // Timeout
    }

    xSemaphoreTake(ringbuf_mutex, portMAX_DELAY);

    if (ringbuf_available == 0) {
        xSemaphoreGive(ringbuf_mutex);
        return 0;
    }

    size_t to_read = (max_len < ringbuf_available) ? max_len : ringbuf_available;

    // Read data, handling wrap-around
    size_t first_chunk = ringbuf_size - ringbuf_tail;
    if (first_chunk >= to_read) {
        // No wrap needed
        memcpy(data, ringbuf_data + ringbuf_tail, to_read);
        ringbuf_tail = (ringbuf_tail + to_read) % ringbuf_size;
    } else {
        // Wrap around
        memcpy(data, ringbuf_data + ringbuf_tail, first_chunk);
        memcpy(data + first_chunk, ringbuf_data, to_read - first_chunk);
        ringbuf_tail = to_read - first_chunk;
    }

    ringbuf_available -= to_read;

    // If more data available, signal again
    if (ringbuf_available > 0) {
        xSemaphoreGive(data_ready_sem);
    }

    xSemaphoreGive(ringbuf_mutex);

    return to_read;
}

size_t ringbuf_peek(uint8_t *data, size_t max_len)
{
    if (ringbuf_data == NULL || ringbuf_mutex == NULL) {
        return 0;
    }

    xSemaphoreTake(ringbuf_mutex, portMAX_DELAY);

    if (ringbuf_available == 0) {
        xSemaphoreGive(ringbuf_mutex);
        return 0;
    }

    size_t to_read = (max_len < ringbuf_available) ? max_len : ringbuf_available;

    // Read data without moving tail, handling wrap-around
    size_t first_chunk = ringbuf_size - ringbuf_tail;
    if (first_chunk >= to_read) {
        memcpy(data, ringbuf_data + ringbuf_tail, to_read);
    } else {
        memcpy(data, ringbuf_data + ringbuf_tail, first_chunk);
        memcpy(data + first_chunk, ringbuf_data, to_read - first_chunk);
    }

    xSemaphoreGive(ringbuf_mutex);

    return to_read;
}

void ringbuf_skip(size_t len)
{
    if (ringbuf_data == NULL || ringbuf_mutex == NULL) {
        return;
    }

    xSemaphoreTake(ringbuf_mutex, portMAX_DELAY);

    if (len > ringbuf_available) {
        len = ringbuf_available;
    }

    ringbuf_tail = (ringbuf_tail + len) % ringbuf_size;
    ringbuf_available -= len;

    xSemaphoreGive(ringbuf_mutex);
}

size_t ringbuf_available_bytes(void)
{
    if (ringbuf_mutex == NULL) {
        return 0;
    }

    xSemaphoreTake(ringbuf_mutex, portMAX_DELAY);
    size_t avail = ringbuf_available;
    xSemaphoreGive(ringbuf_mutex);

    return avail;
}

size_t ringbuf_free_space(void)
{
    if (ringbuf_mutex == NULL) {
        return 0;
    }

    xSemaphoreTake(ringbuf_mutex, portMAX_DELAY);
    size_t free_space = ringbuf_size - ringbuf_available;
    xSemaphoreGive(ringbuf_mutex);

    return free_space;
}

size_t ringbuf_total_size(void)
{
    return ringbuf_size;
}

uint32_t ringbuf_get_dropped_count(void)
{
    return dropped_packets;
}

void ringbuf_reset_dropped_count(void)
{
    dropped_packets = 0;
}
