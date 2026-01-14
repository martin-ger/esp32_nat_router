/* Simple HTTP Server Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#include <esp_wifi.h>
#include <esp_event.h>
#include <esp_log.h>
#include <esp_system.h>
#include <esp_timer.h>
#include <sys/param.h>
//#include "nvs_flash.h"
#include "esp_netif.h"
//#include "esp_eth.h"
//#include "protocol_examples_common.h"

#include <esp_http_server.h>

#include "lwip/lwip_napt.h"

#include "pages.h"
#include "router_globals.h"

static const char *TAG = "HTTPServer";

esp_timer_handle_t restart_timer;

static void restart_timer_callback(void* arg)
{
    ESP_LOGI(TAG, "Restarting now...");
    esp_restart();
}

esp_timer_create_args_t restart_timer_args = {
        .callback = &restart_timer_callback,
        /* argument specified here will be passed to timer callback function */
        .arg = (void*) 0,
        .name = "restart_timer"
};

esp_err_t http_404_error_handler(httpd_req_t *req, httpd_err_code_t err)
{
    httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Page not found");
    return ESP_FAIL;
}

char* html_escape(const char* src) {
    //Primitive html attribue escape, should handle most common issues.
    int len = strlen(src);
    //Every char in the string + a null
    int esc_len = len + 1;

    for (int i = 0; i < len; i++) {
        if (src[i] == '\\' || src[i] == '\'' || src[i] == '\"' || src[i] == '&' || src[i] == '#' || src[i] == ';') {
            //Will be replaced with a 5 char sequence
            esc_len += 4;
        }
    }

    char* res = malloc(sizeof(char) * esc_len);
    if (res == NULL) {
        ESP_LOGE(TAG, "Failed to allocate memory for HTML escaping");
        return NULL;
    }

    int j = 0;
    for (int i = 0; i < len; i++) {
        if (src[i] == '\\' || src[i] == '\'' || src[i] == '\"' || src[i] == '&' || src[i] == '#' || src[i] == ';') {
            res[j++] = '&';
            res[j++] = '#';
            res[j++] = '0' + (src[i] / 10);
            res[j++] = '0' + (src[i] % 10);
            res[j++] = ';';
        }
        else {
            res[j++] = src[i];
        }
    }
    res[j] = '\0';

    return res;
}

/* Index page GET handler - System Status with navigation */
static esp_err_t index_get_handler(httpd_req_t *req)
{
    /* Build status information */
    char conn_status[32];
    char sta_ip_str[32];
    char ap_ip_str[32];

    if (ap_connect) {
        strcpy(conn_status, "Connected");
        esp_ip4_addr_t addr;
        addr.addr = my_ip;
        sprintf(sta_ip_str, IPSTR, IP2STR(&addr));
    } else {
        strcpy(conn_status, "Disconnected");
        strcpy(sta_ip_str, "N/A");
    }

    esp_ip4_addr_t ap_addr;
    ap_addr.addr = my_ap_ip;
    sprintf(ap_ip_str, IPSTR, IP2STR(&ap_addr));

    uint32_t free_heap = esp_get_free_heap_size() / 1024;

    /* Build the page */
    const char* index_page_template = INDEX_PAGE;
    int page_len = strlen(index_page_template) + 512;
    char* index_page = malloc(page_len);

    if (index_page == NULL) {
        ESP_LOGE(TAG, "Failed to allocate memory for index page");
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Out of memory");
        return ESP_ERR_NO_MEM;
    }

    snprintf(index_page, page_len, index_page_template,
        conn_status, sta_ip_str, ap_ip_str, connect_count, free_heap);

    httpd_resp_send(req, index_page, strlen(index_page));
    free(index_page);

    return ESP_OK;
}

static httpd_uri_t indexp = {
    .uri       = "/",
    .method    = HTTP_GET,
    .handler   = index_get_handler,
};

/* Router Config page GET handler */
static esp_err_t config_get_handler(httpd_req_t *req)
{
    char*  buf;
    size_t buf_len;

    /* Read URL query string length and allocate memory for length + 1 */
    buf_len = httpd_req_get_url_query_len(req) + 1;
    if (buf_len > 1) {
        buf = malloc(buf_len);
        if (buf == NULL) {
            ESP_LOGE(TAG, "Failed to allocate memory for query string");
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Out of memory");
            return ESP_ERR_NO_MEM;
        }
        if (httpd_req_get_url_query_str(req, buf, buf_len) == ESP_OK) {
            ESP_LOGI(TAG, "Found URL query => %s", buf);
            if (strcmp(buf, "reset=Reboot") == 0) {
                esp_timer_start_once(restart_timer, 500000);
            }
            char param1[64];
            char param2[64];
            char param3[64];
            char param4[64];
            char param5[64];

            /* Handle AP settings with optional MAC */
            if (httpd_query_key_value(buf, "ap_ssid", param1, sizeof(param1)) == ESP_OK) {
                ESP_LOGI(TAG, "Found URL query parameter => ap_ssid=%s", param1);
                preprocess_string(param1);
                if (httpd_query_key_value(buf, "ap_password", param2, sizeof(param2)) == ESP_OK) {
                    ESP_LOGI(TAG, "Found URL query parameter => ap_password=%s", param2);
                    preprocess_string(param2);

                    // Set SSID and password
                    int argc = 3;
                    char* argv[3];
                    argv[0] = "set_ap";
                    argv[1] = param1;
                    argv[2] = param2;
                    set_ap(argc, argv);

                    // Check for optional AP MAC address
                    if (httpd_query_key_value(buf, "ap_mac", param3, sizeof(param3)) == ESP_OK && strlen(param3) > 0) {
                        ESP_LOGI(TAG, "Found URL query parameter => ap_mac=%s", param3);
                        preprocess_string(param3);
                        // Parse MAC address string (format: AA:BB:CC:DD:EE:FF)
                        unsigned int mac[6];
                        if (sscanf(param3, "%02x:%02x:%02x:%02x:%02x:%02x",
                                   &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6) {
                            char mac_str[6][4];
                            for (int i = 0; i < 6; i++) {
                                sprintf(mac_str[i], "%d", mac[i]);
                            }
                            char* mac_argv[7];
                            mac_argv[0] = "set_ap_mac";
                            for (int i = 0; i < 6; i++) {
                                mac_argv[i+1] = mac_str[i];
                            }
                            set_ap_mac(7, mac_argv);
                        }
                    }
                    esp_timer_start_once(restart_timer, 500000);
                }
            }

            /* Handle STA settings with optional MAC */
            if (httpd_query_key_value(buf, "ssid", param1, sizeof(param1)) == ESP_OK) {
                ESP_LOGI(TAG, "Found URL query parameter => ssid=%s", param1);
                preprocess_string(param1);
                if (httpd_query_key_value(buf, "password", param2, sizeof(param2)) == ESP_OK) {
                    ESP_LOGI(TAG, "Found URL query parameter => password=%s", param2);
                    preprocess_string(param2);
                    if (httpd_query_key_value(buf, "ent_username", param3, sizeof(param3)) == ESP_OK) {
                        ESP_LOGI(TAG, "Found URL query parameter => ent_username=%s", param3);
                        preprocess_string(param3);
                        if (httpd_query_key_value(buf, "ent_identity", param4, sizeof(param4)) == ESP_OK) {
                            ESP_LOGI(TAG, "Found URL query parameter => ent_identity=%s", param4);
                            preprocess_string(param4);

                            int argc = 0;
                            char* argv[7];
                            argv[argc++] = "set_sta";
                            //SSID
                            argv[argc++] = param1;
                            //Password
                            argv[argc++] = param2;
                            //Username
                            if(strlen(param3)) {
                                argv[argc++] = "-u";
                                argv[argc++] = param3;
                            }
                            //Identity
                            if(strlen(param4)) {
                                argv[argc++] = "-a";
                                argv[argc++] = param4;
                            }

                            set_sta(argc, argv);

                            // Check for optional STA MAC address
                            if (httpd_query_key_value(buf, "sta_mac", param5, sizeof(param5)) == ESP_OK && strlen(param5) > 0) {
                                ESP_LOGI(TAG, "Found URL query parameter => sta_mac=%s", param5);
                                preprocess_string(param5);
                                // Parse MAC address string (format: AA:BB:CC:DD:EE:FF)
                                unsigned int mac[6];
                                if (sscanf(param5, "%02x:%02x:%02x:%02x:%02x:%02x",
                                           &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6) {
                                    char mac_str[6][4];
                                    for (int i = 0; i < 6; i++) {
                                        sprintf(mac_str[i], "%d", mac[i]);
                                    }
                                    char* mac_argv[7];
                                    mac_argv[0] = "set_sta_mac";
                                    for (int i = 0; i < 6; i++) {
                                        mac_argv[i+1] = mac_str[i];
                                    }
                                    set_sta_mac(7, mac_argv);
                                }
                            }

                            esp_timer_start_once(restart_timer, 500000);
                        }
                    }
                }
            }

            /* Handle static IP settings */
            if (httpd_query_key_value(buf, "staticip", param1, sizeof(param1)) == ESP_OK) {
                ESP_LOGI(TAG, "Found URL query parameter => staticip=%s", param1);
                preprocess_string(param1);
                if (httpd_query_key_value(buf, "subnetmask", param2, sizeof(param2)) == ESP_OK) {
                    ESP_LOGI(TAG, "Found URL query parameter => subnetmask=%s", param2);
                    preprocess_string(param2);
                    if (httpd_query_key_value(buf, "gateway", param3, sizeof(param3)) == ESP_OK) {
                        ESP_LOGI(TAG, "Found URL query parameter => gateway=%s", param3);
                        preprocess_string(param3);
                        int argc = 4;
                        char* argv[4];
                        argv[0] = "set_sta_static";
                        argv[1] = param1;
                        argv[2] = param2;
                        argv[3] = param3;
                        set_sta_static(argc, argv);
                        esp_timer_start_once(restart_timer, 500000);
                    }
                }
            }
        }
        free(buf);
    }

    /* Build config page with escaped values */
    const char* config_page_template = ROUTER_CONFIG_PAGE;

    char* safe_ap_ssid = html_escape(ap_ssid);
    char* safe_ap_passwd = html_escape(ap_passwd);
    char* safe_ssid = html_escape(ssid);
    char* safe_passwd = html_escape(passwd);
    char* safe_ent_username = html_escape(ent_username);
    char* safe_ent_identity = html_escape(ent_identity);

    // Get MAC addresses as strings
    char ap_mac_str[18] = "";
    char sta_mac_str[18] = "";

    uint8_t mac[6];
    if (esp_wifi_get_mac(ESP_IF_WIFI_AP, mac) == ESP_OK) {
        sprintf(ap_mac_str, "%02X:%02X:%02X:%02X:%02X:%02X",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }
    if (esp_wifi_get_mac(ESP_IF_WIFI_STA, mac) == ESP_OK) {
        sprintf(sta_mac_str, "%02X:%02X:%02X:%02X:%02X:%02X",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }

    // Check if any html_escape failed
    if (safe_ap_ssid == NULL || safe_ap_passwd == NULL || safe_ssid == NULL ||
        safe_passwd == NULL || safe_ent_username == NULL || safe_ent_identity == NULL) {
        ESP_LOGE(TAG, "Failed to escape HTML strings");
        free(safe_ap_ssid);
        free(safe_ap_passwd);
        free(safe_ssid);
        free(safe_passwd);
        free(safe_ent_username);
        free(safe_ent_identity);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Out of memory");
        return ESP_ERR_NO_MEM;
    }

    int page_len =
        strlen(config_page_template) +
        strlen(safe_ap_ssid) +
        strlen(safe_ap_passwd) +
        strlen(safe_ssid) +
        strlen(safe_passwd) +
        strlen(safe_ent_username) +
        strlen(safe_ent_identity) +
        strlen(ap_mac_str) +
        strlen(sta_mac_str) +
        strlen(static_ip) +
        strlen(subnet_mask) +
        strlen(gateway_addr) +
        512;
    char* config_page = malloc(sizeof(char) * page_len);
    if (config_page == NULL) {
        ESP_LOGE(TAG, "Failed to allocate memory for config page");
        free(safe_ap_ssid);
        free(safe_ap_passwd);
        free(safe_ssid);
        free(safe_passwd);
        free(safe_ent_username);
        free(safe_ent_identity);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Out of memory");
        return ESP_ERR_NO_MEM;
    }

    snprintf(
        config_page, page_len, config_page_template,
        safe_ap_ssid, safe_ap_passwd, ap_mac_str,
        safe_ssid, safe_passwd, safe_ent_username, safe_ent_identity, sta_mac_str,
        static_ip, subnet_mask, gateway_addr);

    free(safe_ap_ssid);
    free(safe_ap_passwd);
    free(safe_ssid);
    free(safe_passwd);
    free(safe_ent_username);
    free(safe_ent_identity);

    httpd_resp_send(req, config_page, strlen(config_page));
    free(config_page);

    return ESP_OK;
}

static httpd_uri_t configp = {
    .uri       = "/config",
    .method    = HTTP_GET,
    .handler   = config_get_handler,
};

/* Port Forwarding page GET handler */
static esp_err_t portforward_get_handler(httpd_req_t *req)
{
    char* buf;
    size_t buf_len;

    /* Read URL query string length and allocate memory for length + 1 */
    buf_len = httpd_req_get_url_query_len(req) + 1;
    if (buf_len > 1) {
        buf = malloc(buf_len);
        if (buf == NULL) {
            ESP_LOGE(TAG, "Failed to allocate memory for query string");
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Out of memory");
            return ESP_ERR_NO_MEM;
        }

        if (httpd_req_get_url_query_str(req, buf, buf_len) == ESP_OK) {
            ESP_LOGI(TAG, "Found URL query => %s", buf);

            char param1[64];
            char param2[64];
            char param3[64];
            char param4[64];

            /* Check for add port mapping */
            if (httpd_query_key_value(buf, "action", param1, sizeof(param1)) == ESP_OK) {
                if (strcmp(param1, "Add+Mapping") == 0 || strcmp(param1, "Add Mapping") == 0) {
                    if (httpd_query_key_value(buf, "proto", param1, sizeof(param1)) == ESP_OK &&
                        httpd_query_key_value(buf, "ext_port", param2, sizeof(param2)) == ESP_OK &&
                        httpd_query_key_value(buf, "int_ip", param3, sizeof(param3)) == ESP_OK &&
                        httpd_query_key_value(buf, "int_port", param4, sizeof(param4)) == ESP_OK) {

                        uint8_t proto = (strcmp(param1, "TCP") == 0) ? PROTO_TCP : PROTO_UDP;
                        uint16_t ext_port = atoi(param2);
                        uint32_t int_ip = esp_ip4addr_aton(param3);
                        uint16_t int_port = atoi(param4);

                        add_portmap(proto, ext_port, int_ip, int_port);
                        ESP_LOGI(TAG, "Added port mapping: %s %d -> %s:%d", param1, ext_port, param3, int_port);
                    }
                }
            }

            /* Check for delete port mapping */
            if (httpd_query_key_value(buf, "del_proto", param1, sizeof(param1)) == ESP_OK &&
                httpd_query_key_value(buf, "del_port", param2, sizeof(param2)) == ESP_OK) {
                uint8_t proto = (strcmp(param1, "TCP") == 0) ? PROTO_TCP : PROTO_UDP;
                uint16_t port = atoi(param2);
                del_portmap(proto, port);
                ESP_LOGI(TAG, "Deleted port mapping: %s %d", param1, port);
            }
        }
        free(buf);
    }

    /* Build port mapping table HTML */
    char portmap_html[2048] = "";
    int offset = 0;
    bool has_mappings = false;

    for (int i = 0; i < IP_PORTMAP_MAX; i++) {
        if (portmap_tab[i].valid) {
            has_mappings = true;
            esp_ip4_addr_t addr;
            addr.addr = portmap_tab[i].daddr;

            offset += snprintf(portmap_html + offset, sizeof(portmap_html) - offset,
                "<tr>"
                "<td>%s</td>"
                "<td>%d</td>"
                "<td>" IPSTR "</td>"
                "<td>%d</td>"
                "<td><a href='/portforward?del_proto=%s&del_port=%d' class='red-button small-button'>Delete</a></td>"
                "</tr>",
                portmap_tab[i].proto == PROTO_TCP ? "TCP" : "UDP",
                portmap_tab[i].mport,
                IP2STR(&addr),
                portmap_tab[i].dport,
                portmap_tab[i].proto == PROTO_TCP ? "TCP" : "UDP",
                portmap_tab[i].mport
            );
        }
    }

    if (!has_mappings) {
        snprintf(portmap_html, sizeof(portmap_html),
            "<tr><td colspan='5' style='text-align:center; color:#888;'>No port mappings configured</td></tr>");
    }

    /* Build the page */
    const char* portforward_page_template = PORTFORWARD_PAGE;
    int page_len = strlen(portforward_page_template) + strlen(portmap_html) + 512;
    char* portforward_page = malloc(page_len);

    if (portforward_page == NULL) {
        ESP_LOGE(TAG, "Failed to allocate memory for portforward page");
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Out of memory");
        return ESP_ERR_NO_MEM;
    }

    snprintf(portforward_page, page_len, portforward_page_template, portmap_html);

    httpd_resp_send(req, portforward_page, strlen(portforward_page));
    free(portforward_page);

    return ESP_OK;
}

static httpd_uri_t portforwardp = {
    .uri       = "/portforward",
    .method    = HTTP_GET,
    .handler   = portforward_get_handler,
};

httpd_handle_t start_webserver(void)
{
    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.stack_size = 8192;  // Increase from default 4096 to prevent stack overflow

    esp_timer_create(&restart_timer_args, &restart_timer);

    // Start the httpd server
    ESP_LOGI(TAG, "Starting server on port: '%d'", config.server_port);
    if (httpd_start(&server, &config) == ESP_OK) {
        // Set URI handlers
        ESP_LOGI(TAG, "Registering URI handlers");
        httpd_register_uri_handler(server, &indexp);
        httpd_register_uri_handler(server, &configp);
        httpd_register_uri_handler(server, &portforwardp);
        return server;
    }

    ESP_LOGI(TAG, "Error starting server!");
    return NULL;
}

static void stop_webserver(httpd_handle_t server)
{
    // Stop the httpd server
    httpd_stop(server);
}
