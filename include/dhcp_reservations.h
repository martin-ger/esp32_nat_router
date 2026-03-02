/* DHCP reservation structs, connected-client helpers, and lease queries.
 *
 * SPDX-License-Identifier: MIT
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"
#include "router_config.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_DHCP_RESERVATIONS (AP_MAX_CONNECTIONS + 2)
#define DHCP_RESERVATION_NAME_LEN 32

struct dhcp_reservation_entry {
    uint8_t mac[6];
    uint32_t ip;
    char name[DHCP_RESERVATION_NAME_LEN];
    uint8_t valid;
};

/**
 * @brief Information about a connected client
 */
typedef struct {
    uint8_t mac[6];                          /**< Client MAC address */
    uint32_t ip;                             /**< Client IP (0 if unknown) */
    char name[DHCP_RESERVATION_NAME_LEN];    /**< Device name from reservation (empty if none) */
    bool has_ip;                             /**< True if IP was found in DHCP leases */
} connected_client_t;

/**
 * @brief Structure for DHCP lease information (from custom dhcpserver)
 * @note Defined here to avoid header conflicts with ESP-IDF's built-in dhcpserver.h
 */
typedef struct {
    uint8_t mac[6];       /**< Client MAC address */
    uint32_t ip;          /**< Client IP address (network byte order) */
    uint32_t lease_timer; /**< Remaining lease time in seconds */
    char hostname[DHCP_RESERVATION_NAME_LEN]; /**< Client hostname from DHCP Option 12 */
} dhcp_lease_info_t;

extern struct dhcp_reservation_entry dhcp_reservations[];

esp_err_t get_dhcp_reservations(void);
void print_dhcp_reservations(void);
esp_err_t add_dhcp_reservation(const uint8_t *mac, uint32_t ip, const char *name);
esp_err_t del_dhcp_reservation(const uint8_t *mac);
esp_err_t clear_all_dhcp_reservations(void);
uint32_t lookup_dhcp_reservation(const uint8_t *mac);

/**
 * @brief Look up device name by IP address from DHCP reservations
 * @param ip IP address to look up (network byte order)
 * @return Device name if found, NULL if no reservation with that IP
 */
const char* lookup_device_name_by_ip(uint32_t ip);

/**
 * @brief Look up device name by MAC address from DHCP reservations
 * @param mac MAC address to look up (6 bytes)
 * @return Device name if found, NULL if no reservation with that MAC
 */
const char* lookup_device_name_by_mac(const uint8_t *mac);

/**
 * @brief Resolve a device name to an IP address from DHCP reservations
 * @param name Device name to look up (case-insensitive)
 * @param ip Output IP address (network byte order)
 * @return true if found, false if no reservation with that name
 */
bool resolve_device_name_to_ip(const char *name, uint32_t *ip);

void get_dhcp_pool_range(uint32_t server_ip, uint32_t *start_ip, uint32_t *end_ip);
void print_dhcp_pool(void);

/**
 * @brief Get list of currently connected WiFi clients
 * @param clients Array to store client information
 * @param max_clients Maximum number of clients to return
 * @return Number of connected clients found
 */
int get_connected_clients(connected_client_t *clients, int max_clients);

/**
 * @brief Enumerate all active DHCP leases
 * @param leases Array to store lease information
 * @param max_leases Maximum number of leases to return
 * @return Number of active leases found (0 if DHCP server not running)
 */
int dhcps_get_active_leases(dhcp_lease_info_t *leases, int max_leases);

#ifdef __cplusplus
}
#endif
