/* Console example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include "esp_system.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_console.h"
#include "esp_vfs_dev.h"
#include "driver/gpio.h"
#include "driver/uart.h"
#include "driver/uart_vfs.h"
#include "driver/usb_serial_jtag.h"
#include "driver/usb_serial_jtag_vfs.h"
#include "linenoise/linenoise.h"
#include "argtable3/argtable3.h"
#include "esp_vfs_fat.h"
#include "nvs.h"
#include "nvs_flash.h"

#include "freertos/event_groups.h"
#include "esp_wifi.h"
#include "esp_eap_client.h"

#include "lwip/opt.h"
#include "lwip/err.h"
#include "lwip/sys.h"

#include "dhcpserver/dhcpserver.h"
#include "dhcpserver/dhcpserver_options.h"

#include "cmd_decl.h"
#include <esp_http_server.h>

#if !IP_NAPT
#error "IP_NAPT must be defined"
#endif
#include "lwip/lwip_napt.h"

#include "router_globals.h"
#include "lwip/netif.h"
#include "lwip/ip_addr.h"
#include "esp_netif.h"
#include "pcap_capture.h"
#include "acl.h"
#include "remote_console.h"
#include "oled_display.h"
#include "lwip/prot/ip4.h"
#include "lwip/inet_chksum.h"

// Byte counting variables
uint64_t sta_bytes_sent = 0;
uint64_t sta_bytes_received = 0;

// TTL override for STA upstream (0 = disabled/no change)
uint8_t sta_ttl_override = 0;

// AP SSID hidden (0 = visible, 1 = hidden)
uint8_t ap_ssid_hidden = 0;

// WPA2-Enterprise settings
int32_t eap_method = 0;          // 0=Auto, 1=PEAP, 2=TTLS, 3=TLS
int32_t ttls_phase2 = 0;         // 0=MSCHAPv2, 1=MSCHAP, 2=PAP, 3=CHAP
int32_t use_cert_bundle = 0;     // 0=off, 1=on
int32_t disable_time_check = 0;  // 0=off, 1=on

// Original netif input and linkoutput function pointers
static netif_input_fn original_netif_input = NULL;
static netif_linkoutput_fn original_netif_linkoutput = NULL;
static struct netif *sta_netif = NULL;

// Original AP netif function pointers (for future use)
static netif_input_fn original_ap_netif_input = NULL;
static netif_linkoutput_fn original_ap_netif_linkoutput = NULL;
static struct netif *ap_netif = NULL;

/* FreeRTOS event group to signal when we are connected*/
static EventGroupHandle_t wifi_event_group;

/* The event group allows multiple bits for each event, but we only care about one event
 * - are we connected to the AP with an IP? */
const int WIFI_CONNECTED_BIT = BIT0;

#define DEFAULT_AP_IP "192.168.4.1"
#define DEFAULT_DNS "8.8.8.8"

/* Global vars */
uint16_t connect_count = 0;
bool ap_connect = false;
bool has_static_ip = false;
int led_gpio = -1;  // -1 means LED disabled (none)
uint8_t led_lowactive = 0;  // 0 = active-high (default), 1 = active-low (inverted)
static uint8_t led_toggle = 0;  // Shared toggle state for packet-driven LED flicker

uint32_t my_ip;
uint32_t my_ap_ip;

struct portmap_table_entry portmap_tab[IP_PORTMAP_MAX];
struct dhcp_reservation_entry dhcp_reservations[MAX_DHCP_RESERVATIONS];

esp_netif_t* wifiAP;
esp_netif_t* wifiSTA;

httpd_handle_t start_webserver(void);

static const char *TAG = "ESP32 NAT router";

/* Console command history can be stored to and loaded from a file.
 * The easiest way to do this is to use FATFS filesystem on top of
 * wear_levelling library.
 */
#if CONFIG_STORE_HISTORY

#define MOUNT_PATH "/data"
#define HISTORY_PATH MOUNT_PATH "/history.txt"

static void initialize_filesystem(void)
{
    static wl_handle_t wl_handle;
    const esp_vfs_fat_mount_config_t mount_config = {
            .max_files = 4,
            .format_if_mount_failed = true
    };
    esp_err_t err = esp_vfs_fat_spiflash_mount_rw_wl(MOUNT_PATH, "storage", &mount_config, &wl_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to mount FATFS (%s)", esp_err_to_name(err));
        return;
    }
}
#endif // CONFIG_STORE_HISTORY

static void initialize_nvs(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK( nvs_flash_erase() );
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);
}

esp_err_t apply_portmap_tab() {
    for (int i = 0; i<IP_PORTMAP_MAX; i++) {
        if (portmap_tab[i].valid) {
            ip_portmap_add(portmap_tab[i].proto, my_ip, portmap_tab[i].mport, portmap_tab[i].daddr, portmap_tab[i].dport);
        }
    }
    return ESP_OK;
}

esp_err_t delete_portmap_tab() {
    for (int i = 0; i<IP_PORTMAP_MAX; i++) {
        if (portmap_tab[i].valid) {
            ip_portmap_remove(portmap_tab[i].proto, portmap_tab[i].mport);
        }
    }
    return ESP_OK;
}

void print_portmap_tab() {
    for (int i = 0; i<IP_PORTMAP_MAX; i++) {
        if (portmap_tab[i].valid) {
            printf ("%s", portmap_tab[i].proto == PROTO_TCP?"TCP ":"UDP ");
            ip4_addr_t addr;
            addr.addr = my_ip;
            printf (IPSTR":%d -> ", IP2STR(&addr), portmap_tab[i].mport);

            /* Try to look up device name for destination IP */
            const char *name = lookup_device_name_by_ip(portmap_tab[i].daddr);
            if (name) {
                printf ("%s:%d\n", name, portmap_tab[i].dport);
            } else {
                addr.addr = portmap_tab[i].daddr;
                printf (IPSTR":%d\n", IP2STR(&addr), portmap_tab[i].dport);
            }
        }
    }
}

esp_err_t get_portmap_tab() {
    esp_err_t err;
    nvs_handle_t nvs;
    size_t len;

    err = nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) {
        return err;
    }
    err = nvs_get_blob(nvs, "portmap_tab", NULL, &len);
    if (err == ESP_OK) {
        if (len != sizeof(portmap_tab)) {
            err = ESP_ERR_NVS_INVALID_LENGTH;
        } else {
            err = nvs_get_blob(nvs, "portmap_tab", portmap_tab, &len);
            if (err != ESP_OK) {
                memset(portmap_tab, 0, sizeof(portmap_tab));
            }
        }
    }
    nvs_close(nvs);

    return err;
}

esp_err_t add_portmap(u8_t proto, u16_t mport, u32_t daddr, u16_t dport) {
    esp_err_t err;
    nvs_handle_t nvs;

    for (int i = 0; i<IP_PORTMAP_MAX; i++) {
        if (!portmap_tab[i].valid) {
            portmap_tab[i].proto = proto;
            portmap_tab[i].mport = mport;
            portmap_tab[i].daddr = daddr;
            portmap_tab[i].dport = dport;
            portmap_tab[i].valid = 1;

            err = nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs);
            if (err != ESP_OK) {
                return err;
            }
            err = nvs_set_blob(nvs, "portmap_tab", portmap_tab, sizeof(portmap_tab));
            if (err == ESP_OK) {
                err = nvs_commit(nvs);
                if (err == ESP_OK) {
                    ESP_LOGI(TAG, "New portmap table stored.");
                }
            }
            nvs_close(nvs);

            ip_portmap_add(proto, my_ip, mport, daddr, dport);

            return ESP_OK;
        }
    }
    return ESP_ERR_NO_MEM;
}

esp_err_t del_portmap(u8_t proto, u16_t mport) {
    esp_err_t err;
    nvs_handle_t nvs;

    for (int i = 0; i<IP_PORTMAP_MAX; i++) {
        if (portmap_tab[i].valid && portmap_tab[i].mport == mport && portmap_tab[i].proto == proto) {
            portmap_tab[i].valid = 0;

            err = nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs);
            if (err != ESP_OK) {
                return err;
            }
            err = nvs_set_blob(nvs, "portmap_tab", portmap_tab, sizeof(portmap_tab));
            if (err == ESP_OK) {
                err = nvs_commit(nvs);
                if (err == ESP_OK) {
                    ESP_LOGI(TAG, "New portmap table stored.");
                }
            }
            nvs_close(nvs);

            ip_portmap_remove(proto, mport);
            return ESP_OK;
        }
    }
    return ESP_OK;
}

esp_err_t clear_all_portmaps() {
    esp_err_t err;
    nvs_handle_t nvs;

    // Clear all portmap entries from NAPT
    for (int i = 0; i < IP_PORTMAP_MAX; i++) {
        if (portmap_tab[i].valid) {
            ip_portmap_remove(portmap_tab[i].proto, portmap_tab[i].mport);
            portmap_tab[i].valid = 0;
        }
    }

    // Save cleared table to NVS
    err = nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) {
        return err;
    }
    err = nvs_set_blob(nvs, "portmap_tab", portmap_tab, sizeof(portmap_tab));
    if (err == ESP_OK) {
        err = nvs_commit(nvs);
        if (err == ESP_OK) {
            ESP_LOGI(TAG, "All port mappings cleared.");
        }
    }
    nvs_close(nvs);

    return err;
}

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
        if (len != sizeof(dhcp_reservations)) {
            err = ESP_ERR_NVS_INVALID_LENGTH;
        } else {
            err = nvs_get_blob(nvs, "dhcp_res", dhcp_reservations, &len);
            if (err != ESP_OK) {
                memset(dhcp_reservations, 0, sizeof(dhcp_reservations));
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
    err = nvs_set_blob(nvs, "dhcp_res", dhcp_reservations, sizeof(dhcp_reservations));
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
            err = nvs_set_blob(nvs, "dhcp_res", dhcp_reservations, sizeof(dhcp_reservations));
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
    err = nvs_set_blob(nvs, "dhcp_res", dhcp_reservations, sizeof(dhcp_reservations));
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

/* ACL NVS persistence */
esp_err_t save_acl_rules(void) {
    esp_err_t err;
    nvs_handle_t nvs;

    err = nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) {
        return err;
    }

    /* Save each ACL list */
    const char* acl_keys[MAX_ACL_LISTS] = {"acl_0", "acl_1", "acl_2", "acl_3"};
    for (int i = 0; i < MAX_ACL_LISTS; i++) {
        acl_entry_t* rules = acl_get_rules(i);
        if (rules != NULL) {
            err = nvs_set_blob(nvs, acl_keys[i], rules, sizeof(acl_entry_t) * MAX_ACL_ENTRIES);
            if (err != ESP_OK) {
                ESP_LOGE(TAG, "Failed to save ACL list %d: %s", i, esp_err_to_name(err));
            }
        }
    }

    err = nvs_commit(nvs);
    if (err == ESP_OK) {
        ESP_LOGI(TAG, "ACL rules saved to NVS");
    }
    nvs_close(nvs);
    return err;
}

esp_err_t load_acl_rules(void) {
    esp_err_t err;
    nvs_handle_t nvs;
    size_t len;

    /* Initialize ACL subsystem first */
    acl_init();

    err = nvs_open(PARAM_NAMESPACE, NVS_READONLY, &nvs);
    if (err != ESP_OK) {
        return err;
    }

    /* Load each ACL list */
    const char* acl_keys[MAX_ACL_LISTS] = {"acl_0", "acl_1", "acl_2", "acl_3"};
    for (int i = 0; i < MAX_ACL_LISTS; i++) {
        acl_entry_t* rules = acl_get_rules(i);
        if (rules == NULL) continue;

        len = sizeof(acl_entry_t) * MAX_ACL_ENTRIES;
        err = nvs_get_blob(nvs, acl_keys[i], rules, &len);
        if (err == ESP_OK) {
            /* Count loaded rules and reset hit counters */
            int count = 0;
            for (int j = 0; j < MAX_ACL_ENTRIES; j++) {
                if (rules[j].valid) {
                    count++;
                    rules[j].hit_count = 0;  /* Reset hit counter on boot */
                }
            }
            if (count > 0) {
                ESP_LOGI(TAG, "Loaded %d ACL rules for %s", count, acl_get_name(i));
            }
        } else if (err != ESP_ERR_NVS_NOT_FOUND) {
            ESP_LOGW(TAG, "Failed to load ACL list %d: %s", i, esp_err_to_name(err));
        }
    }

    nvs_close(nvs);
    return ESP_OK;
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

// Hook function to count received bytes via netif input and ACL check
static err_t netif_input_hook(struct pbuf *p, struct netif *netif) {
    bool is_acl_monitored = false;

    // Check to_sta ACL (packets from Internet to ESP32)
    if (!acl_is_empty(ACL_TO_STA)) {
        uint8_t result = acl_check_packet(ACL_TO_STA, p);

        // Check if packet has monitor flag
        is_acl_monitored = (result != ACL_NO_MATCH) && (result & ACL_MONITOR) != 0;

        // Handle deny action (logging done in acl_check_packet)
        if ((result & 0x01) == ACL_DENY && result != ACL_NO_MATCH) {
            // Capture denied packet if monitoring is enabled before dropping
            if (is_acl_monitored && pcap_should_capture(true, false)) {
                pcap_capture_packet(p);
            }
            pbuf_free(p);
            return ERR_OK;
        }
    }

    // Capture packet based on mode and ACL monitor flag (STA interface = false)
    if (pcap_should_capture(is_acl_monitored, false)) {
        pcap_capture_packet(p);
    }

    // Count received bytes and toggle LED
    if (netif == sta_netif && p != NULL) {
        sta_bytes_received += p->tot_len;
        if (led_gpio >= 0 && ap_connect) {
            led_toggle ^= 1;
            gpio_set_level(led_gpio, led_toggle ^ led_lowactive);
        }
    }

    // Call original input function
    if (original_netif_input != NULL) {
        return original_netif_input(p, netif);
    }

    return ERR_VAL;
}


// Hook function to count sent bytes via netif linkoutput and ACL check
static err_t netif_linkoutput_hook(struct netif *netif, struct pbuf *p) {
    bool is_acl_monitored = false;

    // Check from_sta ACL (packets from ESP32 to Internet)
    if (!acl_is_empty(ACL_FROM_STA)) {
        uint8_t result = acl_check_packet(ACL_FROM_STA, p);

        // Check if packet has monitor flag
        is_acl_monitored = (result != ACL_NO_MATCH) && (result & ACL_MONITOR) != 0;

        // Handle deny action (logging done in acl_check_packet)
        if ((result & 0x01) == ACL_DENY && result != ACL_NO_MATCH) {
            // Capture denied packet if monitoring is enabled before dropping
            if (is_acl_monitored && pcap_should_capture(true, false)) {
                pcap_capture_packet(p);
            }
            return ERR_OK;
        }
    }

    // TTL override for upstream packets (must be before PCAP capture)
    // Ethernet header: 14 bytes (6 dst + 6 src + 2 ethertype)
    // Use p->len (first segment) to ensure header is accessible in this pbuf
    if (sta_ttl_override > 0 && p != NULL && p->len >= 14 + sizeof(struct ip_hdr)) {
        uint8_t *payload = (uint8_t *)p->payload;
        // Check ethertype for IPv4 (0x0800)
        if (payload[12] == 0x08 && payload[13] == 0x00) {
            struct ip_hdr *iphdr = (struct ip_hdr *)(payload + 14);
            // Verify it's IPv4
            if (IPH_V(iphdr) == 4) {
                // Read 16-bit word containing TTL and protocol
                uint16_t old_ttl_proto = *(uint16_t *)&iphdr->_ttl;
                iphdr->_ttl = sta_ttl_override;
                uint16_t new_ttl_proto = *(uint16_t *)&iphdr->_ttl;

                // RFC 1624: Incremental checksum update
                // HC' = ~(~HC + ~m + m')
                // where HC = old checksum, m = old value, m' = new value
                uint32_t sum = (uint16_t)~iphdr->_chksum;
                sum += (uint16_t)~old_ttl_proto;
                sum += new_ttl_proto;
                // Fold 32-bit sum to 16 bits
                while (sum >> 16) {
                    sum = (sum & 0xFFFF) + (sum >> 16);
                }
                iphdr->_chksum = (uint16_t)~sum;
            }
        }
    }

    // Capture packet based on mode and ACL monitor flag (STA interface = false)
    if (pcap_should_capture(is_acl_monitored, false)) {
        pcap_capture_packet(p);
    }

    // Count sent bytes and toggle LED
    if (netif == sta_netif && p != NULL) {
        sta_bytes_sent += p->tot_len;
        if (led_gpio >= 0 && ap_connect) {
            led_toggle ^= 1;
            gpio_set_level(led_gpio, led_toggle ^ led_lowactive);
        }
    }

    // Call original linkoutput function
    if (original_netif_linkoutput != NULL) {
        return original_netif_linkoutput(netif, p);
    }

    return ERR_IF;
}

void init_byte_counter(void) {
    if (wifiSTA != NULL && original_netif_input == NULL) {
        // Get the underlying lwIP netif structure
        esp_netif_t *sta_netif_handle = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
        if (sta_netif_handle != NULL) {
            // Access internal lwIP netif - this is internal API but necessary for hooking
            extern struct netif *esp_netif_get_netif_impl(esp_netif_t *esp_netif);
            sta_netif = esp_netif_get_netif_impl(sta_netif_handle);
            
            if (sta_netif != NULL) {
                // Store and hook input function
                original_netif_input = sta_netif->input;
                sta_netif->input = netif_input_hook;
                
                // Store and hook linkoutput function
                original_netif_linkoutput = sta_netif->linkoutput;
                sta_netif->linkoutput = netif_linkoutput_hook;
                
                ESP_LOGI(TAG, "Byte counter initialized for STA interface (input & output)");
            }
        }
    }
}

uint64_t get_sta_bytes_sent(void) {
    return sta_bytes_sent;
}

uint64_t get_sta_bytes_received(void) {
    return sta_bytes_received;
}

void reset_sta_byte_counts(void) {
    sta_bytes_sent = 0;
    sta_bytes_received = 0;
}

void resync_connect_count(void) {
    wifi_sta_list_t sta_list;
    if (esp_wifi_ap_get_sta_list(&sta_list) == ESP_OK) {
        connect_count = sta_list.num;
    }
}

// Uptime functions
uint32_t get_uptime_seconds(void) {
    return (uint32_t)(esp_timer_get_time() / 1000000ULL);
}

void format_uptime(uint32_t seconds, char *buf, size_t buf_len) {
    uint32_t days = seconds / 86400;
    uint32_t hours = (seconds % 86400) / 3600;
    uint32_t mins = (seconds % 3600) / 60;
    uint32_t secs = seconds % 60;

    if (days > 0) {
        snprintf(buf, buf_len, "%lud %02lu:%02lu:%02lu",
                 (unsigned long)days, (unsigned long)hours,
                 (unsigned long)mins, (unsigned long)secs);
    } else {
        snprintf(buf, buf_len, "%02lu:%02lu:%02lu",
                 (unsigned long)hours, (unsigned long)mins, (unsigned long)secs);
    }
}

// AP netif hook functions (for PCAP capture and ACL)
static err_t ap_netif_input_hook(struct pbuf *p, struct netif *netif) {
    bool is_acl_monitored = false;

    // Check to_ap ACL (packets from Clients to ESP32)
    if (!acl_is_empty(ACL_TO_AP)) {
        uint8_t result = acl_check_packet(ACL_TO_AP, p);

        // Check if packet has monitor flag
        is_acl_monitored = (result != ACL_NO_MATCH) && (result & ACL_MONITOR) != 0;

        // Handle deny action (logging done in acl_check_packet)
        if ((result & 0x01) == ACL_DENY && result != ACL_NO_MATCH) {
            // Capture denied packet if monitoring is enabled before dropping
            if (is_acl_monitored && pcap_should_capture(true, true)) {
                pcap_capture_packet(p);
            }
            pbuf_free(p);
            return ERR_OK;
        }
    }

    // Capture packet based on mode and ACL monitor flag (AP interface = true)
    if (pcap_should_capture(is_acl_monitored, true)) {
        pcap_capture_packet(p);
    }

    // Call original input function
    if (original_ap_netif_input != NULL) {
        return original_ap_netif_input(p, netif);
    }

    return ERR_VAL;
}

static err_t ap_netif_linkoutput_hook(struct netif *netif, struct pbuf *p) {
    bool is_acl_monitored = false;

    // Check from_ap ACL (packets from ESP32 to Clients)
    if (!acl_is_empty(ACL_FROM_AP)) {
        uint8_t result = acl_check_packet(ACL_FROM_AP, p);

        // Check if packet has monitor flag
        is_acl_monitored = (result != ACL_NO_MATCH) && (result & ACL_MONITOR) != 0;

        // Handle deny action (logging done in acl_check_packet)
        if ((result & 0x01) == ACL_DENY && result != ACL_NO_MATCH) {
            // Capture denied packet if monitoring is enabled before dropping
            if (is_acl_monitored && pcap_should_capture(true, true)) {
                pcap_capture_packet(p);
            }
            return ERR_OK;
        }
    }

    // Capture packet based on mode and ACL monitor flag (AP interface = true)
    if (pcap_should_capture(is_acl_monitored, true)) {
        pcap_capture_packet(p);
    }

    // Call original linkoutput function
    if (original_ap_netif_linkoutput != NULL) {
        return original_ap_netif_linkoutput(netif, p);
    }

    return ERR_IF;
}

void init_ap_netif_hooks(void) {
    if (wifiAP != NULL && original_ap_netif_input == NULL) {
        // Get the underlying lwIP netif structure for AP
        esp_netif_t *ap_netif_handle = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
        if (ap_netif_handle != NULL) {
            // Access internal lwIP netif - this is internal API but necessary for hooking
            extern struct netif *esp_netif_get_netif_impl(esp_netif_t *esp_netif);
            ap_netif = esp_netif_get_netif_impl(ap_netif_handle);
            
            if (ap_netif != NULL) {
                // Store and hook input function
                original_ap_netif_input = ap_netif->input;
                ap_netif->input = ap_netif_input_hook;
                
                // Store and hook linkoutput function
                original_ap_netif_linkoutput = ap_netif->linkoutput;
                ap_netif->linkoutput = ap_netif_linkoutput_hook;
                
                ESP_LOGI(TAG, "AP netif hooks initialized (input & output)");
            }
        }
    }
}

static void initialize_console(void)
{
    /* Disable buffering on stdin */
    setvbuf(stdin, NULL, _IONBF, 0);

#if CONFIG_ESP_CONSOLE_UART_DEFAULT || CONFIG_ESP_CONSOLE_UART_CUSTOM
    /* Drain stdout before reconfiguring it */
    fflush(stdout);
    fsync(fileno(stdout));
    
    /* Minicom, screen, idf_monitor send CR when ENTER key is pressed */
    uart_vfs_dev_port_set_rx_line_endings(0, ESP_LINE_ENDINGS_CR);
    /* Move the caret to the beginning of the next line on '\n' */
    uart_vfs_dev_port_set_tx_line_endings(0, ESP_LINE_ENDINGS_CRLF);

    /* Configure UART. Note that REF_TICK is used so that the baud rate remains
     * correct while APB frequency is changing in light sleep mode.
     */
    const uart_config_t uart_config = {
            .baud_rate = CONFIG_ESP_CONSOLE_UART_BAUDRATE,
            .data_bits = UART_DATA_8_BITS,
            .parity = UART_PARITY_DISABLE,
            .stop_bits = UART_STOP_BITS_1,
            .source_clk = UART_SCLK_DEFAULT,
    };
    /* Install UART driver for interrupt-driven reads and writes */
    ESP_ERROR_CHECK( uart_driver_install(CONFIG_ESP_CONSOLE_UART_NUM,
            256, 0, 0, NULL, 0) );
    ESP_ERROR_CHECK( uart_param_config(CONFIG_ESP_CONSOLE_UART_NUM, &uart_config) );

    /* Tell VFS to use UART driver */
    uart_vfs_dev_use_driver(CONFIG_ESP_CONSOLE_UART_NUM);
#endif

#if CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG
    /* Enable non-blocking mode on stdin and stdout */
    fcntl(fileno(stdout), F_SETFL, O_NONBLOCK);
    fcntl(fileno(stdin), F_SETFL, O_NONBLOCK);

    /* Minicom, screen, idf_monitor send CR when ENTER key is pressed */
    usb_serial_jtag_vfs_set_rx_line_endings(ESP_LINE_ENDINGS_CR);

    /* Move the caret to the beginning of the next line on '\n' */
    usb_serial_jtag_vfs_set_tx_line_endings(ESP_LINE_ENDINGS_CRLF);
    usb_serial_jtag_driver_config_t usb_serial_jtag_config = {
        .tx_buffer_size = 256,
        .rx_buffer_size = 256,
    };

    /* Install USB-SERIAL-JTAG driver for interrupt-driven reads and writes */
    usb_serial_jtag_driver_install(&usb_serial_jtag_config);

    /* Tell vfs to use usb-serial-jtag driver */
    usb_serial_jtag_vfs_use_driver();
#endif

    /* Initialize the console */
    esp_console_config_t console_config = {
            .max_cmdline_args = 12,
            .max_cmdline_length = 256,
#if CONFIG_LOG_COLORS
            .hint_color = atoi(LOG_COLOR_CYAN)
#endif
    };
    ESP_ERROR_CHECK( esp_console_init(&console_config) );

    /* Configure linenoise line completion library */
    /* Enable multiline editing. If not set, long commands will scroll within
     * single line.
     */
    linenoiseSetMultiLine(1);

    /* Tell linenoise where to get command completions and hints */
    linenoiseSetCompletionCallback(&esp_console_get_completion);
    linenoiseSetHintsCallback((linenoiseHintsCallback*) &esp_console_get_hint);

    /* Set command history size */
    linenoiseHistorySetMaxLen(100);

#if CONFIG_STORE_HISTORY
    /* Load command history from filesystem */
    linenoiseHistoryLoad(HISTORY_PATH);
#endif
}

// BOOT button is GPIO 9 on ESP32-C3/C2/C6, GPIO 0 on ESP32/S2/S3
#if defined(CONFIG_IDF_TARGET_ESP32C3) || defined(CONFIG_IDF_TARGET_ESP32C2) || defined(CONFIG_IDF_TARGET_ESP32C6)
#define BOOT_BUTTON_GPIO      9
#else
#define BOOT_BUTTON_GPIO      0
#endif
#define FACTORY_RESET_HOLD_MS 5000
#define POLL_INTERVAL_MS      50

void * led_status_thread(void * p)
{
    // Always init boot button for factory reset detection
    gpio_reset_pin(BOOT_BUTTON_GPIO);
    gpio_set_direction(BOOT_BUTTON_GPIO, GPIO_MODE_INPUT);
    gpio_set_pull_mode(BOOT_BUTTON_GPIO, GPIO_PULLUP_ONLY);

    bool led_enabled = (led_gpio >= 0);
    if (led_enabled) {
        ESP_LOGI(TAG, "LED status on GPIO %d%s", led_gpio, led_lowactive ? " (low-active)" : "");
        gpio_reset_pin(led_gpio);
        gpio_set_direction(led_gpio, GPIO_MODE_OUTPUT);
    } else {
        ESP_LOGI(TAG, "LED status disabled (no GPIO configured)");
    }

    int held_ms = 0;

    while (true)
    {
        // --- LED status: OFF=disconnected, ON=connected (packet hooks flicker it off) ---
        if (led_enabled && held_ms == 0) {
            gpio_set_level(led_gpio, ap_connect ^ led_lowactive);
        }

        // --- Poll interval with button polling ---
        for (int t = 0; t < 1000 / POLL_INTERVAL_MS; t++) {
            vTaskDelay(pdMS_TO_TICKS(POLL_INTERVAL_MS));

            if (gpio_get_level(BOOT_BUTTON_GPIO) == 0) {
                held_ms += POLL_INTERVAL_MS;
                // Rapid LED toggle for visual feedback during hold
                if (led_enabled) {
                    gpio_set_level(led_gpio, ((held_ms / POLL_INTERVAL_MS) % 2) ^ led_lowactive);
                }
                if (held_ms >= FACTORY_RESET_HOLD_MS) {
                    ESP_LOGW(TAG, "BOOT button held %d ms - factory reset!", held_ms);
                    nvs_handle_t nvs;
                    if (nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs) == ESP_OK) {
                        nvs_erase_all(nvs);
                        nvs_commit(nvs);
                        nvs_close(nvs);
                    }
                    esp_restart();
                }
            } else {
                held_ms = 0;
            }
        }
    }
}

static void wifi_event_handler(void* arg, esp_event_base_t event_base,
                                int32_t event_id, void* event_data)
{
    esp_netif_dns_info_t dns;

    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START)
    {
        esp_wifi_connect();
    }
    else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED)
    {
        ESP_LOGI(TAG,"disconnected - retry to connect to the AP");
        ap_connect = false;
        esp_wifi_connect();
        ESP_LOGI(TAG, "retry to connect to the AP");
        xEventGroupClearBits(wifi_event_group, WIFI_CONNECTED_BIT);
    }
    else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP)
    {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        ESP_LOGI(TAG, "got ip:" IPSTR, IP2STR(&event->ip_info.ip));
        ap_connect = true;
        my_ip = event->ip_info.ip.addr;
        delete_portmap_tab();
        apply_portmap_tab();
        if (esp_netif_get_dns_info(wifiSTA, ESP_NETIF_DNS_MAIN, &dns) == ESP_OK)
        {
            esp_netif_set_dns_info(wifiAP, ESP_NETIF_DNS_MAIN, &dns);
            ESP_LOGI(TAG, "set dns to:" IPSTR, IP2STR(&(dns.ip.u_addr.ip4)));
        }
        
        // Initialize byte counter after getting IP (interface is ready)
        init_byte_counter();
        
        xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_BIT);
    }
    else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_START)
    {
        ESP_LOGI(TAG, "AP started");
        // Initialize AP netif hooks now that interface is ready
        init_ap_netif_hooks();
    }
    else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STACONNECTED)
    {
        wifi_event_ap_staconnected_t* event = (wifi_event_ap_staconnected_t*) event_data;
        connect_count++;

        /* Look up device name from DHCP reservations */
        const char* name = lookup_device_name_by_mac(event->mac);
        if (name) {
            ESP_LOGI(TAG, "Client connected: %02X:%02X:%02X:%02X:%02X:%02X (%s) - %d total",
                     event->mac[0], event->mac[1], event->mac[2],
                     event->mac[3], event->mac[4], event->mac[5],
                     name, connect_count);
        } else {
            ESP_LOGI(TAG, "Client connected: %02X:%02X:%02X:%02X:%02X:%02X - %d total",
                     event->mac[0], event->mac[1], event->mac[2],
                     event->mac[3], event->mac[4], event->mac[5],
                     connect_count);
        }
    }
    else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STADISCONNECTED)
    {
        wifi_event_ap_stadisconnected_t* event = (wifi_event_ap_stadisconnected_t*) event_data;
        connect_count--;

        /* Look up device name from DHCP reservations */
        const char* name = lookup_device_name_by_mac(event->mac);
        if (name) {
            ESP_LOGI(TAG, "Client disconnected: %02X:%02X:%02X:%02X:%02X:%02X (%s) - %d remain",
                     event->mac[0], event->mac[1], event->mac[2],
                     event->mac[3], event->mac[4], event->mac[5],
                     name, connect_count);
        } else {
            ESP_LOGI(TAG, "Client disconnected: %02X:%02X:%02X:%02X:%02X:%02X - %d remain",
                     event->mac[0], event->mac[1], event->mac[2],
                     event->mac[3], event->mac[4], event->mac[5],
                     connect_count);
        }
    }
}

const int CONNECTED_BIT = BIT0;
#define JOIN_TIMEOUT_MS (2000)


void wifi_init(const uint8_t* mac, const char* ssid, const char* ent_username, const char* ent_identity, const char* passwd, const char* static_ip, const char* subnet_mask, const char* gateway_addr, const uint8_t* ap_mac, const char* ap_ssid, const char* ap_passwd, const char* ap_ip)
{
    esp_netif_dns_info_t dnsserver;
    // esp_netif_dns_info_t dnsinfo;

    wifi_event_group = xEventGroupCreate();
  
    esp_netif_init();
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    wifiAP = esp_netif_create_default_wifi_ap();
    wifiSTA = esp_netif_create_default_wifi_sta();

    esp_netif_ip_info_t ipInfo_sta;
    if ((strlen(ssid) > 0) && (strlen(static_ip) > 0) && (strlen(subnet_mask) > 0) && (strlen(gateway_addr) > 0)) {
        has_static_ip = true;
        ipInfo_sta.ip.addr = esp_ip4addr_aton(static_ip);
        ipInfo_sta.gw.addr = esp_ip4addr_aton(gateway_addr);
        ipInfo_sta.netmask.addr = esp_ip4addr_aton(subnet_mask);
        esp_netif_dhcpc_stop(wifiSTA); // Don't run a DHCP client
        esp_netif_set_ip_info(wifiSTA, &ipInfo_sta);
        apply_portmap_tab();
    }

    my_ap_ip = esp_ip4addr_aton(ap_ip);

    esp_netif_ip_info_t ipInfo_ap;
    ipInfo_ap.ip.addr = my_ap_ip;
    ipInfo_ap.gw.addr = my_ap_ip;
    esp_netif_set_ip4_addr(&ipInfo_ap.netmask, 255,255,255,0);
    esp_netif_dhcps_stop(wifiAP); // stop before setting ip WifiAP
    esp_netif_set_ip_info(wifiAP, &ipInfo_ap);
    esp_netif_dhcps_start(wifiAP);

    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &wifi_event_handler,
                                                        NULL,
                                                        &instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                                                        IP_EVENT_STA_GOT_IP,
                                                        &wifi_event_handler,
                                                        NULL,
                                                        &instance_got_ip));

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    /* ESP WIFI CONFIG */
    wifi_config_t wifi_config = { 0 };
        wifi_config_t ap_config = {
        .ap = {
            .channel = 0,
            .authmode = WIFI_AUTH_WPA2_WPA3_PSK,
            .ssid_hidden = ap_ssid_hidden,
            .max_connection = AP_MAX_CONNECTIONS,
            .beacon_interval = 100,
        }
    };

    strlcpy((char*)ap_config.sta.ssid, ap_ssid, sizeof(ap_config.sta.ssid));
    if (strlen(ap_passwd) < 8) {
        ap_config.ap.authmode = WIFI_AUTH_OPEN;
    } else {
	    strlcpy((char*)ap_config.sta.password, ap_passwd, sizeof(ap_config.sta.password));
    }

    // Always use APSTA mode so WiFi scanning works even without an uplink configured
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA) );

    if (strlen(ssid) > 0) {
        //Set SSID
        strlcpy((char*)wifi_config.sta.ssid, ssid, sizeof(wifi_config.sta.ssid));
        //Set password
        if(strlen(ent_username) == 0) {
            ESP_LOGI(TAG, "STA regular connection");
            strlcpy((char*)wifi_config.sta.password, passwd, sizeof(wifi_config.sta.password));
        }
        ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config) );
        if(strlen(ent_username) != 0) {
            ESP_LOGI(TAG, "STA enterprise connection");
            if(strlen(ent_identity) != 0) {
                esp_eap_client_set_identity((uint8_t *)ent_identity, strlen(ent_identity));
            } else {
                esp_eap_client_set_identity((uint8_t *)ent_username, strlen(ent_username));
            }
            esp_eap_client_set_username((uint8_t *)ent_username, strlen(ent_username));
            esp_eap_client_set_password((uint8_t *)passwd, strlen(passwd));

            // Set TTLS phase 2 method
            if (ttls_phase2 >= 0 && ttls_phase2 <= 3) {
                esp_eap_client_set_ttls_phase2_method(ttls_phase2);
            }

            // Use CA certificate bundle for server validation
#ifdef CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
            if (use_cert_bundle) {
                esp_eap_client_use_default_cert_bundle(true);
            }
#endif

            // Disable certificate time check
            if (disable_time_check) {
                esp_eap_client_set_disable_time_check(true);
            }

            esp_wifi_sta_enterprise_enable();
        }

        if (mac != NULL) {
            ESP_ERROR_CHECK(esp_wifi_set_mac(ESP_IF_WIFI_STA, mac));
        }
    }

    ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_AP, &ap_config) );

    if (ap_mac != NULL) {
        ESP_ERROR_CHECK(esp_wifi_set_mac(ESP_IF_WIFI_AP, ap_mac));
    }


    // Enable DNS (offer) for dhcp server
    dhcps_offer_t dhcps_dns_value = OFFER_DNS;
    esp_netif_dhcps_option(wifiAP,ESP_NETIF_OP_SET, ESP_NETIF_DOMAIN_NAME_SERVER, &dhcps_dns_value, sizeof(dhcps_dns_value));

    // // Set custom dns server address for dhcp server
    dnsserver.ip.u_addr.ip4.addr = esp_ip4addr_aton(DEFAULT_DNS);
    dnsserver.ip.type = ESP_IPADDR_TYPE_V4;
    esp_netif_set_dns_info(wifiAP, ESP_NETIF_DNS_MAIN, &dnsserver);

    // esp_netif_get_dns_info(ESP_IF_WIFI_AP, ESP_NETIF_DNS_MAIN, &dnsinfo);
    // ESP_LOGI(TAG, "DNS IP:" IPSTR, IP2STR(&dnsinfo.ip.u_addr.ip4));

    xEventGroupWaitBits(wifi_event_group, CONNECTED_BIT,
        pdFALSE, pdTRUE, pdMS_TO_TICKS(JOIN_TIMEOUT_MS));
    ESP_ERROR_CHECK(esp_wifi_start());

    if (strlen(ssid) > 0) {
        ESP_LOGI(TAG, "wifi_init_apsta finished.");
        ESP_LOGI(TAG, "connect to ap SSID: %s ", ssid);
    } else {
        ESP_LOGI(TAG, "wifi_init_ap with default finished.");      
    }
}

uint8_t* mac = NULL;
char* ssid = NULL;
char* ent_username = NULL;
char* ent_identity = NULL;
char* passwd = NULL;
char* static_ip = NULL;
char* subnet_mask = NULL;
char* gateway_addr = NULL;
uint8_t* ap_mac = NULL;
char* ap_ssid = NULL;
char* ap_passwd = NULL;
char* ap_ip = NULL;

char* param_set_default(const char* def_val) {
    char * retval = malloc(strlen(def_val)+1);
    if (retval == NULL) {
        ESP_LOGE(TAG, "Failed to allocate memory for default parameter");
        return NULL;
    }
    strcpy(retval, def_val);
    return retval;
}

void app_main(void)
{
    initialize_nvs();
    load_log_level();  // Apply saved log level early

#if CONFIG_STORE_HISTORY
    initialize_filesystem();
    ESP_LOGI(TAG, "Command history enabled");
#else
    ESP_LOGI(TAG, "Command history disabled");
#endif

    get_config_param_blob("mac", &mac, 6);
    get_config_param_str("ssid", &ssid);
    if (ssid == NULL) {
        ssid = param_set_default("");
    }
    get_config_param_str("ent_username", &ent_username);
    if (ent_username == NULL) {
        ent_username = param_set_default("");
    }
    get_config_param_str("ent_identity", &ent_identity);
    if (ent_identity == NULL) {
        ent_identity = param_set_default("");
    }
    get_config_param_str("passwd", &passwd);
    if (passwd == NULL) {
        passwd = param_set_default("");
    }
    get_config_param_str("static_ip", &static_ip);
    if (static_ip == NULL) {
        static_ip = param_set_default("");
    }
    get_config_param_str("subnet_mask", &subnet_mask);
    if (subnet_mask == NULL) {
        subnet_mask = param_set_default("");
    }
    get_config_param_str("gateway_addr", &gateway_addr);
    if (gateway_addr == NULL) {
        gateway_addr = param_set_default("");
    }
    get_config_param_blob("ap_mac", &ap_mac, 6);
    get_config_param_str("ap_ssid", &ap_ssid);
    if (ap_ssid == NULL) {
        ap_ssid = param_set_default("ESP32_NAT_Router");
    }   
    get_config_param_str("ap_passwd", &ap_passwd);
    if (ap_passwd == NULL) {
        ap_passwd = param_set_default("");
    }
    get_config_param_str("ap_ip", &ap_ip);
    if (ap_ip == NULL) {
        ap_ip = param_set_default(DEFAULT_AP_IP);
    }

    get_portmap_tab();
    get_dhcp_reservations();
    load_acl_rules();

    // Load LED GPIO setting from NVS (default -1 = disabled)
    int led_gpio_setting = -1;
    if (get_config_param_int("led_gpio", &led_gpio_setting) == ESP_OK) {
        led_gpio = led_gpio_setting;
    }
    // led_gpio remains -1 (disabled) if not set in NVS

    // Load LED low-active setting from NVS (default 0 = active-high)
    int led_lowactive_setting = 0;
    if (get_config_param_int("led_low", &led_lowactive_setting) == ESP_OK) {
        led_lowactive = (led_lowactive_setting != 0) ? 1 : 0;
    }
    if (led_lowactive) {
        ESP_LOGI(TAG, "LED low-active mode enabled");
    }

    // Load TTL override setting from NVS (default 0 = disabled)
    int ttl_setting = 0;
    if (get_config_param_int("sta_ttl", &ttl_setting) == ESP_OK) {
        if (ttl_setting >= 0 && ttl_setting <= 255) {
            sta_ttl_override = (uint8_t)ttl_setting;
        }
    }
    if (sta_ttl_override > 0) {
        ESP_LOGI(TAG, "TTL override enabled: %d", sta_ttl_override);
    }

    // Load AP SSID hidden setting from NVS (default 0 = visible)
    int hidden_setting = 0;
    if (get_config_param_int("ap_hidden", &hidden_setting) == ESP_OK) {
        ap_ssid_hidden = (hidden_setting != 0) ? 1 : 0;
    }
    if (ap_ssid_hidden) {
        ESP_LOGI(TAG, "AP SSID hidden enabled");
    }

    // Load WPA2-Enterprise settings from NVS (defaults: 0)
    int eap_setting = 0;
    if (get_config_param_int("eap_method", &eap_setting) == ESP_OK) {
        eap_method = (int32_t)eap_setting;
    }
    int phase2_setting = 0;
    if (get_config_param_int("ttls_phase2", &phase2_setting) == ESP_OK) {
        ttls_phase2 = (int32_t)phase2_setting;
    }
    int cert_bundle_setting = 0;
    if (get_config_param_int("cert_bundle", &cert_bundle_setting) == ESP_OK) {
        use_cert_bundle = (int32_t)cert_bundle_setting;
    }
    int time_check_setting = 0;
    if (get_config_param_int("no_time_chk", &time_check_setting) == ESP_OK) {
        disable_time_check = (int32_t)time_check_setting;
    }

    // Setup WIFI
    wifi_init(mac, ssid, ent_username, ent_identity, passwd, static_ip, subnet_mask, gateway_addr, ap_mac, ap_ssid, ap_passwd, ap_ip);

    pthread_t t1;
    pthread_create(&t1, NULL, led_status_thread, NULL);

    ip_napt_enable(my_ap_ip, 1);
    ESP_LOGI(TAG, "NAT is enabled");

    char* web_disabled = NULL;
    get_config_param_str("lock", &web_disabled);
    if (web_disabled == NULL) {
        web_disabled = param_set_default("0");
    }
    if (strcmp(web_disabled, "0") ==0) {
        ESP_LOGI(TAG,"Starting web server");
        start_webserver();
    }
    free(web_disabled);

    // Initialize PCAP capture (TCP server on port 19000)
    pcap_init();

    // Initialize remote console (TCP server on port 2323, disabled by default)
    remote_console_init();

    // Initialize OLED display (disabled by default, enable via 'set_oled enable')
    oled_display_init();

    initialize_console();

    /* Register commands */
    esp_console_register_help_command();
    register_system();
    register_router();

    /* Prompt to be printed before each line.
     * This can be customized, made dynamic, etc.
     */
    const char* prompt = LOG_COLOR_I "esp32> " LOG_RESET_COLOR;

    printf("\n"
           "ESP32 NAT ROUTER\n"
           "Type 'help' to get the list of commands.\n"
           "Use UP/DOWN arrows to navigate through command history.\n"
           "Press TAB when typing command name to auto-complete.\n");

    if (strlen(ssid) == 0) {
         printf("\n"
               "Unconfigured WiFi\n"
               "Configure using 'set_sta' and 'set_ap' and restart.\n");       
    }

    /* Figure out if the terminal supports escape sequences */
    int probe_status = linenoiseProbe();
    if (probe_status) { /* zero indicates success */
        printf("\n"
               "Your terminal application does not support escape sequences.\n"
               "Line editing and history features are disabled.\n"
               "On Windows, try using Putty instead.\n");
        linenoiseSetDumbMode(1);
#if CONFIG_LOG_COLORS
        /* Since the terminal doesn't support escape sequences,
         * don't use color codes in the prompt.
         */
        prompt = "esp32> ";
#endif //CONFIG_LOG_COLORS
    }

    /* Main loop */
    while(true) {
        /* Get a line using linenoise.
         * The line is returned when ENTER is pressed.
         */
        char* line = linenoise(prompt);
        if (line == NULL) { /* Ignore empty lines */
            continue;
        }
        /* Add the command to the history */
        linenoiseHistoryAdd(line);
#if CONFIG_STORE_HISTORY
        /* Save command history to filesystem */
        linenoiseHistorySave(HISTORY_PATH);
#endif

        /* Try to run the command */
        int ret;
        esp_err_t err = esp_console_run(line, &ret);
        if (err == ESP_ERR_NOT_FOUND) {
            printf("Unrecognized command\n");
        } else if (err == ESP_ERR_INVALID_ARG) {
            // command was empty
        } else if (err == ESP_OK && ret != ESP_OK) {
            printf("Command returned non-zero error code: 0x%x (%s)\n", ret, esp_err_to_name(ret));
        } else if (err != ESP_OK) {
            printf("Internal error: %s\n", esp_err_to_name(err));
        }
        /* linenoise allocates line buffer on the heap, so need to free it */
        linenoiseFree(line);
    }
}
