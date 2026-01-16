/* Various global declarations for the esp32_nat_router

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PARAM_NAMESPACE "esp32_nat"

#define PROTO_TCP 6
#define PROTO_UDP 17

#define MAX_DHCP_RESERVATIONS 16
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

struct portmap_table_entry {
    uint32_t daddr;
    uint16_t mport;
    uint16_t dport;
    uint8_t proto;
    uint8_t valid;
};

extern struct portmap_table_entry portmap_tab[];
extern struct dhcp_reservation_entry dhcp_reservations[];

extern char* ssid;
extern char* ent_username;
extern char* ent_identity;
extern char* passwd;
extern char* static_ip;
extern char* subnet_mask;
extern char* gateway_addr;
extern char* ap_ssid;
extern char* ap_passwd;

extern uint16_t connect_count;
extern bool ap_connect;

extern uint32_t my_ip;
extern uint32_t my_ap_ip;

// Byte counting variables for STA interface
extern uint64_t sta_bytes_sent;
extern uint64_t sta_bytes_received;

void preprocess_string(char* str);
int set_sta(int argc, char **argv);
int set_sta_static(int argc, char **argv);
int set_sta_mac(int argc, char **argv);
int set_ap(int argc, char **argv);
int set_ap_mac(int argc, char **argv);
int set_ap_ip(int argc, char **argv);

esp_err_t get_config_param_blob(char* name, uint8_t** blob, size_t blob_len);
esp_err_t get_config_param_int(char* name, int* param);
esp_err_t get_config_param_str(char* name, char** param);

void print_portmap_tab();
esp_err_t add_portmap(uint8_t proto, uint16_t mport, uint32_t daddr, uint16_t dport);
esp_err_t del_portmap(uint8_t proto, uint16_t mport);
esp_err_t clear_all_portmaps();

esp_err_t get_dhcp_reservations();
void print_dhcp_reservations();
esp_err_t add_dhcp_reservation(const uint8_t *mac, uint32_t ip, const char *name);
esp_err_t del_dhcp_reservation(const uint8_t *mac);
esp_err_t clear_all_dhcp_reservations();
uint32_t lookup_dhcp_reservation(const uint8_t *mac);

void get_dhcp_pool_range(uint32_t server_ip, uint32_t *start_ip, uint32_t *end_ip);
void print_dhcp_pool();

/**
 * @brief Get list of currently connected WiFi clients
 * @param clients Array to store client information
 * @param max_clients Maximum number of clients to return
 * @return Number of connected clients found
 */
int get_connected_clients(connected_client_t *clients, int max_clients);

/**
 * @brief Structure for DHCP lease information (from custom dhcpserver)
 * @note Defined here to avoid header conflicts with ESP-IDF's built-in dhcpserver.h
 */
typedef struct {
    uint8_t mac[6];       /**< Client MAC address */
    uint32_t ip;          /**< Client IP address (network byte order) */
    uint32_t lease_timer; /**< Remaining lease time in seconds */
} dhcp_lease_info_t;

/**
 * @brief Enumerate all active DHCP leases
 * @param leases Array to store lease information
 * @param max_leases Maximum number of leases to return
 * @return Number of active leases found (0 if DHCP server not running)
 */
int dhcps_get_active_leases(dhcp_lease_info_t *leases, int max_leases);

// Byte counting functions
void init_byte_counter(void);
uint64_t get_sta_bytes_sent(void);
uint64_t get_sta_bytes_received(void);
void reset_sta_byte_counts(void);

// AP netif hook functions (for future use)
void init_ap_netif_hooks(void);

#ifdef __cplusplus
}
#endif
