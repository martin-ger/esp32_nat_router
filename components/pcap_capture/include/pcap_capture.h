/* PCAP Capture - Capture AP interface traffic and stream via TCP

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "lwip/pbuf.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize PCAP capture system and start TCP server task
 *
 * Creates ring buffer, starts TCP server listening on port 19000.
 * Capture is disabled by default, use pcap_capture_start() to enable.
 */
void pcap_init(void);

/**
 * @brief Capture a packet into the ring buffer
 *
 * Called from AP netif hooks. Non-blocking - if buffer is full,
 * packet is dropped and counter incremented.
 *
 * @param p Packet buffer to capture
 */
void pcap_capture_packet(struct pbuf *p);

/**
 * @brief Enable packet capture
 */
void pcap_capture_start(void);

/**
 * @brief Disable packet capture
 */
void pcap_capture_stop(void);

/**
 * @brief Check if capture is enabled
 * @return true if capture is enabled
 */
bool pcap_capture_enabled(void);

/**
 * @brief Check if a client is connected to the TCP server
 * @return true if client is connected
 */
bool pcap_client_connected(void);

/**
 * @brief Get count of captured packets
 * @return Number of packets captured since last start
 */
uint32_t pcap_get_captured_count(void);

/**
 * @brief Get count of dropped packets (buffer overflow)
 * @return Number of packets dropped since last reset
 */
uint32_t pcap_get_dropped_count(void);

/**
 * @brief Get current ring buffer usage
 * @param used Returns bytes currently in buffer
 * @param total Returns total buffer size
 */
void pcap_get_buffer_usage(size_t *used, size_t *total);

/**
 * @brief Get current snaplen (max captured bytes per packet)
 * @return Current snaplen value
 */
uint16_t pcap_get_snaplen(void);

/**
 * @brief Set snaplen (max captured bytes per packet)
 * @param snaplen Value between 64 and 1600
 * @return true on success, false if value out of range
 */
bool pcap_set_snaplen(uint16_t snaplen);

#ifdef __cplusplus
}
#endif
