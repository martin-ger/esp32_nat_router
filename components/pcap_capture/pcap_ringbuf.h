/* PCAP Ring Buffer - Internal header

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "freertos/FreeRTOS.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize the ring buffer
 * @param size Buffer size in bytes
 * @return true on success, false on failure
 */
bool ringbuf_init(size_t size);

/**
 * @brief Reset the ring buffer (clear all data)
 */
void ringbuf_reset(void);

/**
 * @brief Write data to ring buffer (non-blocking)
 * @param data Data to write
 * @param len Length of data
 * @return true on success, false if buffer full or busy
 */
bool ringbuf_write(const uint8_t *data, size_t len);

/**
 * @brief Read data from ring buffer (blocking with timeout)
 * @param data Buffer to read into
 * @param max_len Maximum bytes to read
 * @param timeout Timeout in ticks
 * @return Number of bytes read
 */
size_t ringbuf_read(uint8_t *data, size_t max_len, TickType_t timeout);

/**
 * @brief Peek at data without removing it
 * @param data Buffer to read into
 * @param max_len Maximum bytes to peek
 * @return Number of bytes peeked
 */
size_t ringbuf_peek(uint8_t *data, size_t max_len);

/**
 * @brief Skip/discard bytes from buffer
 * @param len Number of bytes to skip
 */
void ringbuf_skip(size_t len);

/**
 * @brief Get number of bytes available to read
 * @return Bytes available
 */
size_t ringbuf_available_bytes(void);

/**
 * @brief Get free space in buffer
 * @return Free bytes
 */
size_t ringbuf_free_space(void);

/**
 * @brief Get total buffer size
 * @return Total size
 */
size_t ringbuf_total_size(void);

/**
 * @brief Get count of dropped packets due to buffer full
 * @return Dropped packet count
 */
uint32_t ringbuf_get_dropped_count(void);

/**
 * @brief Reset dropped packet counter
 */
void ringbuf_reset_dropped_count(void);

#ifdef __cplusplus
}
#endif
