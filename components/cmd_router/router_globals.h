/* Various global declarations for the esp32_nat_router

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#pragma once

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

#ifdef __cplusplus
}
#endif
