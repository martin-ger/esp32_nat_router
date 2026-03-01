/* DHCP reservation management with NVS persistence.
 *
 * Manages fixed IP address assignments for clients based on MAC address,
 * with optional device names for user-friendly identification.
 */

#include <string.h>
#include <strings.h>
#include "esp_log.h"
#include "nvs.h"
#include "lwip/ip4_addr.h"
#include "dhcpserver/dhcpserver.h"
#include "esp_wifi.h"
#include "router_globals.h"

#define DHCP_RES_SIZE (sizeof(struct dhcp_reservation_entry) * MAX_DHCP_RESERVATIONS)

static const char *TAG = "dhcp_mgr";

esp_err_t get_dhcp_reservations() {
    esp_err_t err;
    nvs_handle_t nvs;
    size_t len;

    err = nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) {
        return err;
    }
    err = nvs_get_blob(nvs, "dhcp_res", NULL, &len);
    if (err == ESP_OK) {
        if (len != DHCP_RES_SIZE) {
            err = ESP_ERR_NVS_INVALID_LENGTH;
        } else {
            err = nvs_get_blob(nvs, "dhcp_res", dhcp_reservations, &len);
            if (err != ESP_OK) {
                memset(dhcp_reservations, 0, DHCP_RES_SIZE);
            }
        }
    }
    nvs_close(nvs);

    return err;
}

void print_dhcp_reservations() {
    for (int i = 0; i < MAX_DHCP_RESERVATIONS; i++) {
        if (dhcp_reservations[i].valid) {
            ip4_addr_t addr;
            addr.addr = dhcp_reservations[i].ip;
            printf("%02X:%02X:%02X:%02X:%02X:%02X -> " IPSTR,
                dhcp_reservations[i].mac[0], dhcp_reservations[i].mac[1],
                dhcp_reservations[i].mac[2], dhcp_reservations[i].mac[3],
                dhcp_reservations[i].mac[4], dhcp_reservations[i].mac[5],
                IP2STR(&addr));
            if (dhcp_reservations[i].name[0] != '\0') {
                printf(" (%s)", dhcp_reservations[i].name);
            }
            printf("\n");
        }
    }
}

void get_dhcp_pool_range(uint32_t server_ip, uint32_t *start_ip, uint32_t *end_ip) {
    // DHCP pool calculation logic (mirrors dhcps_poll_set in dhcpserver.c)
    // Default netmask is 255.255.255.0
    uint32_t netmask = 0xFFFFFF00; // 255.255.255.0 in host byte order
    uint32_t server_ip_host = ntohl(server_ip);
    uint32_t range_start_ip = server_ip_host & netmask;
    uint32_t range_end_ip = range_start_ip | ~netmask;

    // Determine which side of the server IP has more addresses
    if (server_ip_host - range_start_ip > range_end_ip - server_ip_host) {
        // More addresses before server IP
        range_start_ip = range_start_ip + 1;
        range_end_ip = server_ip_host - 1;
    } else {
        // More addresses after server IP
        range_start_ip = server_ip_host + 1;
        range_end_ip = range_end_ip - 1;
    }

    // Limit to DHCPS_MAX_LEASE (100 addresses) - already defined in dhcpserver.h
    if (range_end_ip - range_start_ip + 1 > DHCPS_MAX_LEASE) {
        range_end_ip = range_start_ip + DHCPS_MAX_LEASE - 1;
    }

    *start_ip = htonl(range_start_ip);
    *end_ip = htonl(range_end_ip);
}

void print_dhcp_pool() {
    uint32_t start_ip, end_ip;
    get_dhcp_pool_range(my_ap_ip, &start_ip, &end_ip);

    ip4_addr_t start_addr, end_addr;
    start_addr.addr = start_ip;
    end_addr.addr = end_ip;

    printf("DHCP Pool: " IPSTR " - " IPSTR " (%lu addresses)\n",
        IP2STR(&start_addr), IP2STR(&end_addr),
        (unsigned long)(ntohl(end_ip) - ntohl(start_ip) + 1));
}

esp_err_t add_dhcp_reservation(const uint8_t *mac, uint32_t ip, const char *name) {
    esp_err_t err;
    nvs_handle_t nvs;

    // Check if MAC already exists and update it
    for (int i = 0; i < MAX_DHCP_RESERVATIONS; i++) {
        if (dhcp_reservations[i].valid &&
            memcmp(dhcp_reservations[i].mac, mac, 6) == 0) {
            // Update existing entry
            dhcp_reservations[i].ip = ip;
            if (name != NULL) {
                strncpy(dhcp_reservations[i].name, name, DHCP_RESERVATION_NAME_LEN - 1);
                dhcp_reservations[i].name[DHCP_RESERVATION_NAME_LEN - 1] = '\0';
            } else {
                dhcp_reservations[i].name[0] = '\0';
            }
            goto save;
        }
    }

    // Find first empty slot
    for (int i = 0; i < MAX_DHCP_RESERVATIONS; i++) {
        if (!dhcp_reservations[i].valid) {
            memcpy(dhcp_reservations[i].mac, mac, 6);
            dhcp_reservations[i].ip = ip;
            if (name != NULL) {
                strncpy(dhcp_reservations[i].name, name, DHCP_RESERVATION_NAME_LEN - 1);
                dhcp_reservations[i].name[DHCP_RESERVATION_NAME_LEN - 1] = '\0';
            } else {
                dhcp_reservations[i].name[0] = '\0';
            }
            dhcp_reservations[i].valid = 1;
            goto save;
        }
    }
    return ESP_ERR_NO_MEM;

save:
    err = nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) {
        return err;
    }
    err = nvs_set_blob(nvs, "dhcp_res", dhcp_reservations, DHCP_RES_SIZE);
    if (err == ESP_OK) {
        err = nvs_commit(nvs);
        if (err == ESP_OK) {
            ESP_LOGI(TAG, "DHCP reservations stored.");
        }
    }
    nvs_close(nvs);
    return ESP_OK;
}

esp_err_t del_dhcp_reservation(const uint8_t *mac) {
    esp_err_t err;
    nvs_handle_t nvs;

    for (int i = 0; i < MAX_DHCP_RESERVATIONS; i++) {
        if (dhcp_reservations[i].valid &&
            memcmp(dhcp_reservations[i].mac, mac, 6) == 0) {
            dhcp_reservations[i].valid = 0;

            err = nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs);
            if (err != ESP_OK) {
                return err;
            }
            err = nvs_set_blob(nvs, "dhcp_res", dhcp_reservations, DHCP_RES_SIZE);
            if (err == ESP_OK) {
                err = nvs_commit(nvs);
                if (err == ESP_OK) {
                    ESP_LOGI(TAG, "DHCP reservations stored.");
                }
            }
            nvs_close(nvs);
            return ESP_OK;
        }
    }
    return ESP_OK;
}

esp_err_t clear_all_dhcp_reservations() {
    esp_err_t err;
    nvs_handle_t nvs;

    // Clear all reservation entries
    for (int i = 0; i < MAX_DHCP_RESERVATIONS; i++) {
        dhcp_reservations[i].valid = 0;
    }

    // Save cleared table to NVS
    err = nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) {
        return err;
    }
    err = nvs_set_blob(nvs, "dhcp_res", dhcp_reservations, DHCP_RES_SIZE);
    if (err == ESP_OK) {
        err = nvs_commit(nvs);
        if (err == ESP_OK) {
            ESP_LOGI(TAG, "All DHCP reservations cleared.");
        }
    }
    nvs_close(nvs);

    return err;
}

uint32_t lookup_dhcp_reservation(const uint8_t *mac) {
    for (int i = 0; i < MAX_DHCP_RESERVATIONS; i++) {
        if (dhcp_reservations[i].valid &&
            memcmp(dhcp_reservations[i].mac, mac, 6) == 0) {
            return dhcp_reservations[i].ip;
        }
    }
    return 0;
}

const char* lookup_device_name_by_ip(uint32_t ip) {
    for (int i = 0; i < MAX_DHCP_RESERVATIONS; i++) {
        if (dhcp_reservations[i].valid &&
            dhcp_reservations[i].ip == ip &&
            dhcp_reservations[i].name[0] != '\0') {
            return dhcp_reservations[i].name;
        }
    }
    return NULL;
}

const char* lookup_device_name_by_mac(const uint8_t *mac) {
    for (int i = 0; i < MAX_DHCP_RESERVATIONS; i++) {
        if (dhcp_reservations[i].valid &&
            memcmp(dhcp_reservations[i].mac, mac, 6) == 0 &&
            dhcp_reservations[i].name[0] != '\0') {
            return dhcp_reservations[i].name;
        }
    }
    return NULL;
}

bool resolve_device_name_to_ip(const char *name, uint32_t *ip) {
    if (name == NULL || ip == NULL) {
        return false;
    }
    for (int i = 0; i < MAX_DHCP_RESERVATIONS; i++) {
        if (dhcp_reservations[i].valid &&
            dhcp_reservations[i].name[0] != '\0' &&
            strcasecmp(dhcp_reservations[i].name, name) == 0) {
            *ip = dhcp_reservations[i].ip;
            return true;
        }
    }
    return false;
}

int get_connected_clients(connected_client_t *clients, int max_clients) {
    if (clients == NULL || max_clients <= 0) {
        return 0;
    }

    // Get list of connected WiFi stations
    wifi_sta_list_t sta_list;
    esp_err_t err = esp_wifi_ap_get_sta_list(&sta_list);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Failed to get station list: %s", esp_err_to_name(err));
        return 0;
    }

    // Get DHCP lease information (static to avoid stack overflow)
    #define MAX_DHCP_LEASES 8  // ESP32 AP supports max 8 connections
    static dhcp_lease_info_t leases[MAX_DHCP_LEASES];
    int lease_count = dhcps_get_active_leases(leases, MAX_DHCP_LEASES);

    int count = 0;
    for (int i = 0; i < sta_list.num && count < max_clients; i++) {
        wifi_sta_info_t *sta = &sta_list.sta[i];

        // Copy MAC address
        memcpy(clients[count].mac, sta->mac, 6);
        clients[count].ip = 0;
        clients[count].has_ip = false;
        clients[count].name[0] = '\0';

        // Look up IP address and hostname in DHCP leases
        for (int j = 0; j < lease_count; j++) {
            if (memcmp(leases[j].mac, sta->mac, 6) == 0) {
                clients[count].ip = leases[j].ip;
                clients[count].has_ip = true;
                // Use DHCP hostname if provided by client
                if (leases[j].hostname[0] != '\0') {
                    strncpy(clients[count].name, leases[j].hostname,
                            DHCP_RESERVATION_NAME_LEN - 1);
                    clients[count].name[DHCP_RESERVATION_NAME_LEN - 1] = '\0';
                }
                break;
            }
        }

        // Look up device name in DHCP reservations (overrides DHCP hostname)
        for (int j = 0; j < MAX_DHCP_RESERVATIONS; j++) {
            if (dhcp_reservations[j].valid &&
                memcmp(dhcp_reservations[j].mac, sta->mac, 6) == 0) {
                // Reservation name takes priority over DHCP hostname
                if (dhcp_reservations[j].name[0] != '\0') {
                    strncpy(clients[count].name, dhcp_reservations[j].name,
                            DHCP_RESERVATION_NAME_LEN - 1);
                    clients[count].name[DHCP_RESERVATION_NAME_LEN - 1] = '\0';
                }
                break;
            }
        }

        count++;
    }

    return count;
}
