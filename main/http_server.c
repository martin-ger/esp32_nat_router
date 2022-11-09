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

/* An HTTP GET handler */
static esp_err_t index_get_handler(httpd_req_t *req)
{
    char*  buf;
    size_t buf_len;

    /* Get header value string length and allocate memory for length + 1,
     * extra byte for null termination */
    buf_len = httpd_req_get_hdr_value_len(req, "Host") + 1;
    if (buf_len > 1) {
        buf = malloc(buf_len);
        /* Copy null terminated value string into buffer */
        if (httpd_req_get_hdr_value_str(req, "Host", buf, buf_len) == ESP_OK) {
            ESP_LOGI(TAG, "Found header => Host: %s", buf);
        }
        free(buf);
    }

    /* Read URL query string length and allocate memory for length + 1,
     * extra byte for null termination */
    buf_len = httpd_req_get_url_query_len(req) + 1;
    if (buf_len > 1) {
        buf = malloc(buf_len);
        if (httpd_req_get_url_query_str(req, buf, buf_len) == ESP_OK) {
            ESP_LOGI(TAG, "Found URL query => %s", buf);
            if (strcmp(buf, "reset=Reboot") == 0) {
                esp_timer_start_once(restart_timer, 500000);
            }
            char param1[64];
            char param2[64];
            char param3[64];
            char param4[64];
            /* Get value of expected key from query string */
            if (httpd_query_key_value(buf, "ap_ssid", param1, sizeof(param1)) == ESP_OK) {
                ESP_LOGI(TAG, "Found URL query parameter => ap_ssid=%s", param1);
                preprocess_string(param1);
                if (httpd_query_key_value(buf, "ap_password", param2, sizeof(param2)) == ESP_OK) {
                    ESP_LOGI(TAG, "Found URL query parameter => ap_password=%s", param2);
                    preprocess_string(param2);
                    int argc = 3;
                    char* argv[3];
                    argv[0] = "set_ap";
                    argv[1] = param1;
                    argv[2] = param2;
                    set_ap(argc, argv);
                    esp_timer_start_once(restart_timer, 500000);
                }
            }
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
                            if(strlen(param2)) {
                                argv[argc++] = "-u";
                                argv[argc++] = param3;
                            }
                            //Identity
                            if(strlen(param3)) {
                                argv[argc++] = "-a";
                                argv[argc++] = param4;
                            }
                            
                    set_sta(argc, argv);
                    esp_timer_start_once(restart_timer, 500000);
                        }
                    }
                }
            }
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

    /* Send response with custom headers and body set as the
     * string passed in user context*/
    const char* resp_str = (const char*) req->user_ctx;
    httpd_resp_send(req, resp_str, strlen(resp_str));

    return ESP_OK;
}

static httpd_uri_t indexp = {
    .uri       = "/",
    .method    = HTTP_GET,
    .handler   = index_get_handler,
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

httpd_handle_t start_webserver(void)
{
    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();

    const char* config_page_template = CONFIG_PAGE;

    char* safe_ap_ssid = html_escape(ap_ssid);
    char* safe_ap_passwd = html_escape(ap_passwd);
    char* safe_ssid = html_escape(ssid);
    char* safe_passwd = html_escape(passwd);
    char* safe_ent_username = html_escape(ent_username);
    char* safe_ent_identity = html_escape(ent_identity);

    int page_len =
        strlen(config_page_template) +
        strlen(safe_ap_ssid) +
        strlen(safe_ap_passwd) +
        strlen(safe_ssid) +
        strlen(safe_passwd) +
        strlen(safe_ent_username) +
        strlen(safe_ent_identity) +
        256;
    char* config_page = malloc(sizeof(char) * page_len);

    snprintf(
        config_page, page_len, config_page_template,
        safe_ap_ssid, safe_ap_passwd,
        safe_ssid, safe_passwd, safe_ent_username, safe_ent_identity,
            static_ip, subnet_mask, gateway_addr);
    indexp.user_ctx = config_page;

    free(safe_ap_ssid);
    free(safe_ap_passwd);
    free(safe_ssid);
    free(safe_passwd);
    free(safe_ent_username);
    free(safe_ent_identity);

    esp_timer_create(&restart_timer_args, &restart_timer);

    // Start the httpd server
    ESP_LOGI(TAG, "Starting server on port: '%d'", config.server_port);
    if (httpd_start(&server, &config) == ESP_OK) {
        // Set URI handlers
        ESP_LOGI(TAG, "Registering URI handlers");
        httpd_register_uri_handler(server, &indexp);
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
