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
#include "nvs_flash.h"
#include "esp_netif.h"
//#include "esp_eth.h"
//#include "protocol_examples_common.h"

#include <esp_http_server.h>

#include "lwip/lwip_napt.h"

#include "pages.h"
#include "favicon_png.h"
#include "router_globals.h"

static const char *TAG = "HTTPServer";

esp_timer_handle_t restart_timer;

/* Session management for password protection */
#define MAX_SESSION_TOKEN_LEN 32
#define SESSION_TIMEOUT_US (30 * 60 * 1000000LL) // 30 minutes

static char current_session_token[MAX_SESSION_TOKEN_LEN + 1] = {0};
static bool session_active = false;
static int64_t session_expiry_time = 0;

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

/* Session management helper functions */

/* Generate random session token */
static void generate_session_token(char* token_out, size_t len)
{
    const char hex_chars[] = "0123456789abcdef";
    for (size_t i = 0; i < len - 1; i++) {
        token_out[i] = hex_chars[esp_random() % 16];
    }
    token_out[len - 1] = '\0';
}

/* Clear session state */
static void clear_session(void)
{
    session_active = false;
    current_session_token[0] = '\0';
    session_expiry_time = 0;
}

/* Load password from NVS (returns true if password is set and non-empty) */
static bool get_web_password(char* password_out, size_t max_len)
{
    nvs_handle_t nvs;
    esp_err_t err = nvs_open(PARAM_NAMESPACE, NVS_READONLY, &nvs);
    if (err != ESP_OK) {
        return false;
    }

    size_t required_size = max_len;
    err = nvs_get_str(nvs, "web_password", password_out, &required_size);
    nvs_close(nvs);

    if (err != ESP_OK || required_size == 0 || password_out[0] == '\0') {
        return false;  // No password set or empty password
    }

    return true;
}

/* Extract cookie value from request headers */
static bool get_cookie_value(httpd_req_t *req, const char* cookie_name,
                              char* value_out, size_t max_len)
{
    size_t cookie_header_len = httpd_req_get_hdr_value_len(req, "Cookie");
    if (cookie_header_len == 0) {
        return false;
    }

    char* cookie_header = malloc(cookie_header_len + 1);
    if (cookie_header == NULL) {
        return false;
    }

    if (httpd_req_get_hdr_value_str(req, "Cookie", cookie_header, cookie_header_len + 1) != ESP_OK) {
        free(cookie_header);
        return false;
    }

    // Search for the cookie name
    char search_pattern[64];
    snprintf(search_pattern, sizeof(search_pattern), "%s=", cookie_name);
    char* cookie_start = strstr(cookie_header, search_pattern);

    if (cookie_start == NULL) {
        free(cookie_header);
        return false;
    }

    // Move past the "name=" part
    cookie_start += strlen(search_pattern);

    // Find the end of the cookie value (semicolon or end of string)
    char* cookie_end = strchr(cookie_start, ';');
    size_t cookie_len = cookie_end ? (size_t)(cookie_end - cookie_start) : strlen(cookie_start);

    if (cookie_len >= max_len) {
        cookie_len = max_len - 1;
    }

    strncpy(value_out, cookie_start, cookie_len);
    value_out[cookie_len] = '\0';

    free(cookie_header);
    return true;
}

/* Check if request has valid session cookie */
static bool is_authenticated(httpd_req_t *req)
{
    // If no session is active, not authenticated
    if (!session_active) {
        return false;
    }

    // Check if session has expired
    int64_t current_time = esp_timer_get_time();
    if (current_time > session_expiry_time) {
        clear_session();
        return false;
    }

    // Extract session cookie
    char session_token[MAX_SESSION_TOKEN_LEN + 1];
    if (!get_cookie_value(req, "session", session_token, sizeof(session_token))) {
        return false;
    }

    // Validate token matches
    if (strcmp(session_token, current_session_token) != 0) {
        return false;
    }

    // Extend session expiry on successful auth
    session_expiry_time = current_time + SESSION_TIMEOUT_US;

    return true;
}

/* Cookie header buffer - must be static because httpd_resp_set_hdr stores pointer, not copy */
static char session_cookie_header[128];

/* Create new session and set cookie */
static esp_err_t create_session(httpd_req_t *req)
{
    // Generate new session token
    generate_session_token(current_session_token, sizeof(current_session_token));

    // Set session active and expiry
    session_active = true;
    session_expiry_time = esp_timer_get_time() + SESSION_TIMEOUT_US;

    // Set cookie in response (using static buffer because httpd stores pointer)
    snprintf(session_cookie_header, sizeof(session_cookie_header),
             "session=%s; Path=/; SameSite=Strict", current_session_token);
    httpd_resp_set_hdr(req, "Set-Cookie", session_cookie_header);

    ESP_LOGI(TAG, "Session created, expires in 30 minutes");
    return ESP_OK;
}

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

static esp_err_t favicon_get_handler(httpd_req_t *req) {
    httpd_resp_set_type(req, "image/png");
    httpd_resp_send(req, (const char*)favicon_png, favicon_png_len);
    return ESP_OK;
}

static const httpd_uri_t favicon_uri = {
    .uri       = "/favicon.png",
    .method    = HTTP_GET,
    .handler   = favicon_get_handler,
    .user_ctx  = NULL
};

/* Index page GET handler - System Status with navigation */
static esp_err_t index_get_handler(httpd_req_t *req)
{
    char* buf = NULL;
    size_t buf_len = 0;
    char param[128];
    char param2[128];
    char login_message[256] = "";
    bool authenticated = false;
    char password[64];
    bool password_protection_enabled = get_web_password(password, sizeof(password));

    /* Get query string if any */
    buf_len = httpd_req_get_url_query_len(req) + 1;
    if (buf_len > 1) {
        buf = malloc(buf_len);
        if (buf != NULL && httpd_req_get_url_query_str(req, buf, buf_len) == ESP_OK) {

            /* Handle logout */
            if (httpd_query_key_value(buf, "logout", param, sizeof(param)) == ESP_OK) {
                clear_session();
                strcpy(login_message, "Logged out successfully.");
            }

            /* Handle login */
            else if (httpd_query_key_value(buf, "login_password", param, sizeof(param)) == ESP_OK) {
                preprocess_string(param);
                if (password_protection_enabled && strcmp(param, password) == 0) {
                    create_session(req);
                    free(buf);
                    /* Redirect to reload page with session cookie */
                    httpd_resp_set_status(req, "303 See Other");
                    httpd_resp_set_hdr(req, "Location", "/");
                    httpd_resp_send(req, NULL, 0);
                    return ESP_OK;
                } else {
                    strcpy(login_message, "ERROR: Incorrect password.");
                }
            }

            /* Handle password change */
            else if (httpd_query_key_value(buf, "new_password", param, sizeof(param)) == ESP_OK &&
                     httpd_query_key_value(buf, "confirm_password", param2, sizeof(param2)) == ESP_OK) {
                preprocess_string(param);
                preprocess_string(param2);

                // Check if user is authenticated or no password is currently set
                if (is_authenticated(req) || !password_protection_enabled) {
                    if (strcmp(param, param2) == 0) {
                        nvs_handle_t nvs;
                        esp_err_t err = nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs);
                        if (err == ESP_OK) {
                            nvs_set_str(nvs, "web_password", param);
                            nvs_commit(nvs);
                            nvs_close(nvs);
                            clear_session();  // Force re-login with new password
                            free(buf);
                            /* Redirect to reload page */
                            httpd_resp_set_status(req, "303 See Other");
                            httpd_resp_set_hdr(req, "Location", "/");
                            httpd_resp_send(req, NULL, 0);
                            return ESP_OK;
                        } else {
                            strcpy(login_message, "ERROR: Failed to save password.");
                        }
                    } else {
                        strcpy(login_message, "ERROR: Passwords do not match.");
                    }
                } else {
                    strcpy(login_message, "ERROR: Not authorized to change password.");
                }
            }

            /* Check for auth_required flag */
            else if (httpd_query_key_value(buf, "auth_required", param, sizeof(param)) == ESP_OK) {
                strcpy(login_message, "Please log in to access that page.");
            }
        }
        if (buf) free(buf);
    }

    /* Check current authentication status */
    authenticated = is_authenticated(req);

    /* Build status information */
    char conn_status[32];
    char sta_ip_str[32];
    char ap_ip_str[32];
    char dhcp_pool_str[64];

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

    // Get DHCP pool range
    uint32_t start_ip, end_ip;
    get_dhcp_pool_range(my_ap_ip, &start_ip, &end_ip);
    esp_ip4_addr_t start_addr, end_addr;
    start_addr.addr = start_ip;
    end_addr.addr = end_ip;
    sprintf(dhcp_pool_str, IPSTR " - " IPSTR, IP2STR(&start_addr), IP2STR(&end_addr));

    // Get byte counts and convert to MB
    uint64_t bytes_sent = get_sta_bytes_sent();
    uint64_t bytes_received = get_sta_bytes_received();
    float sent_mb = bytes_sent / (1024.0 * 1024.0);
    float received_mb = bytes_received / (1024.0 * 1024.0);

    /* Build header section with logout button */
    char header_ui[320] = "";
    if (authenticated) {
        snprintf(header_ui, sizeof(header_ui),
                 "<div style='text-align: right; margin-bottom: 0.5rem;'>"
                 "<a href='/?logout=1' style='padding: 0.4rem 1rem; background: rgba(255,82,82,0.15); color: #ff5252; border: 1px solid #ff5252; border-radius: 6px; text-decoration: none; font-size: 0.85rem; font-weight: 500;'>Logout</a>"
                 "</div>");
    }

    /* Build authentication UI section */
    char auth_ui[2048] = "";

    /* Show message if any */
    if (login_message[0] != '\0') {
        const char* msg_style;
        if (strstr(login_message, "ERROR") != NULL) {
            msg_style = "background: #ffebee; color: #c62828; border: 2px solid #ef5350";
        } else {
            msg_style = "background: #e8f5e9; color: #2e7d32; border: 2px solid #66bb6a";
        }
        snprintf(auth_ui + strlen(auth_ui), sizeof(auth_ui) - strlen(auth_ui),
                 "<div style='margin-top: 1.5rem; padding: 1rem; %s; border-radius: 8px; font-size: 0.95rem;'>%s</div>",
                 msg_style, login_message);
    }

    /* Show warning if no password protection */
    if (!password_protection_enabled) {
        snprintf(auth_ui + strlen(auth_ui), sizeof(auth_ui) - strlen(auth_ui),
                 "<div style='margin-top: 1.5rem; padding: 1rem; background: #fff3cd; border: 2px solid #ffa726; border-radius: 8px;'>"
                 "<strong style='color: #f57c00;'>⚠ No Password Protection</strong>"
                 "<p style='margin-top: 0.5rem; color: #666; font-size: 0.9rem;'>Anyone on this network can access router settings. Set a password below.</p>"
                 "</div>");
    }

    /* Show login form if password is set and not authenticated */
    if (password_protection_enabled && !authenticated) {
        snprintf(auth_ui + strlen(auth_ui), sizeof(auth_ui) - strlen(auth_ui),
                 "<div style='margin-top: 1.5rem; padding: 1.5rem; background: rgba(22, 33, 62, 0.6); border: 1px solid rgba(0, 217, 255, 0.2); border-radius: 12px;'>"
                 "<h2 style='margin-top: 0; margin-bottom: 1rem; color: #00d9ff; font-size: 1.1rem;'>🔒 Login Required</h2>"
                 "<form action='' method='GET'>"
                 "<input type='password' name='login_password' placeholder='Enter password' style='width: 100%%; padding: 0.75rem; margin-bottom: 0.75rem; background: rgba(255,255,255,0.1); border: 1px solid rgba(0,217,255,0.3); border-radius: 8px; color: #e0e0e0; font-size: 1rem;'/>"
                 "<input type='submit' value='Login' style='width: 100%%; padding: 0.75rem; background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); color: #fff; border: none; border-radius: 8px; font-size: 1rem; font-weight: 600; cursor: pointer;'/>"
                 "</form>"
                 "</div>");
    }

    /* Show password management form if authenticated or no password set */
    if (authenticated || !password_protection_enabled) {
        const char* form_title = password_protection_enabled ? "Change Password" : "Set Password";
        snprintf(auth_ui + strlen(auth_ui), sizeof(auth_ui) - strlen(auth_ui),
                 "<div style='margin-top: 1.5rem; padding: 1.5rem; background: rgba(22, 33, 62, 0.6); border: 1px solid rgba(0, 217, 255, 0.2); border-radius: 12px;'>"
                 "<h2 style='margin-top: 0; margin-bottom: 1rem; color: #00d9ff; font-size: 1.1rem;'>🔑 %s</h2>"
                 "<form action='' method='GET'>"
                 "<input type='password' name='new_password' placeholder='New password (empty to disable)' style='width: 100%%; padding: 0.75rem; margin-bottom: 0.75rem; background: rgba(255,255,255,0.1); border: 1px solid rgba(0,217,255,0.3); border-radius: 8px; color: #e0e0e0; font-size: 1rem;'/>"
                 "<input type='password' name='confirm_password' placeholder='Confirm password' style='width: 100%%; padding: 0.75rem; margin-bottom: 0.75rem; background: rgba(255,255,255,0.1); border: 1px solid rgba(0,217,255,0.3); border-radius: 8px; color: #e0e0e0; font-size: 1rem;'/>"
                 "<input type='submit' value='%s' style='width: 100%%; padding: 0.75rem; background: linear-gradient(135deg, #f093fb 0%%, #f5576c 100%%); color: #fff; border: none; border-radius: 8px; font-size: 1rem; font-weight: 600; cursor: pointer;'/>"
                 "<p style='margin-top: 0.75rem; color: #888; font-size: 0.85rem;'>Leave empty to disable password protection.</p>"
                 "</form>"
                 "</div>",
                 form_title, form_title);
    }

    /* Build the page */
    const char* index_page_template = INDEX_PAGE;
    int page_len = strlen(index_page_template) + strlen(header_ui) + strlen(auth_ui) + 512;
    char* index_page = malloc(page_len);

    if (index_page == NULL) {
        ESP_LOGE(TAG, "Failed to allocate memory for index page");
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Out of memory");
        return ESP_ERR_NO_MEM;
    }

    snprintf(index_page, page_len, index_page_template,
        header_ui, conn_status, sta_ip_str, ap_ip_str, dhcp_pool_str, connect_count, sent_mb, received_mb, auth_ui);

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
    /* Check authentication if password protection is enabled */
    char password[64];
    bool password_protection_enabled = get_web_password(password, sizeof(password));

    if (password_protection_enabled && !is_authenticated(req)) {
        /* Redirect to index page with auth_required flag */
        httpd_resp_set_status(req, "303 See Other");
        httpd_resp_set_hdr(req, "Location", "/?auth_required=1");
        httpd_resp_send(req, NULL, 0);
        return ESP_OK;
    }

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

            /* Handle disable interface button */
            if (strstr(buf, "disable_interface=") != NULL) {
                ESP_LOGI(TAG, "Disabling web interface");
                nvs_handle_t nvs;
                esp_err_t err = nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs);
                if (err == ESP_OK) {
                    nvs_set_str(nvs, "lock", "1");
                    nvs_commit(nvs);
                    nvs_close(nvs);
                    ESP_LOGI(TAG, "Web interface disabled. Use 'enable' command via serial to re-enable.");
                }
                esp_timer_start_once(restart_timer, 500000);
            }

            char param1[64];
            char param2[64];
            char param3[64];
            char param4[64];
            char param5[64];

            /* Handle AP settings with optional MAC and IP */
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

                    // Check for optional AP IP address
                    if (httpd_query_key_value(buf, "ap_ip_addr", param3, sizeof(param3)) == ESP_OK && strlen(param3) > 0) {
                        ESP_LOGI(TAG, "Found URL query parameter => ap_ip_addr=%s", param3);
                        preprocess_string(param3);
                        char* ip_argv[2];
                        ip_argv[0] = "set_ap_ip";
                        ip_argv[1] = param3;
                        set_ap_ip(2, ip_argv);
                    }

                    // Check for optional AP MAC address
                    if (httpd_query_key_value(buf, "ap_mac", param4, sizeof(param4)) == ESP_OK && strlen(param4) > 0) {
                        ESP_LOGI(TAG, "Found URL query parameter => ap_mac=%s", param4);
                        preprocess_string(param4);
                        // Parse MAC address string (format: AA:BB:CC:DD:EE:FF)
                        unsigned int mac[6];
                        if (sscanf(param4, "%02x:%02x:%02x:%02x:%02x:%02x",
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

    /* Check session status for logout button */
    bool session_active_for_logout = session_active && password_protection_enabled;
    char logout_section[256] = "";
    if (session_active_for_logout) {
        snprintf(logout_section, sizeof(logout_section),
                 "<a href='/?logout=1' style='padding: 0.4rem 1rem; background: rgba(255,82,82,0.15); color: #ff5252; border: 1px solid #ff5252; border-radius: 6px; text-decoration: none; font-size: 0.85rem; font-weight: 500;'>Logout</a>");
    }

    /* Build config page with escaped values */
    const char* config_page_template = ROUTER_CONFIG_PAGE;

    char* safe_ap_ssid = html_escape(ap_ssid);
    char* safe_ap_passwd = html_escape(ap_passwd);
    char* safe_ssid = html_escape(ssid);
    char* safe_passwd = html_escape(passwd);
    char* safe_ent_username = html_escape(ent_username);
    char* safe_ent_identity = html_escape(ent_identity);

    // Get current AP IP address
    char* ap_ip_str = NULL;
    get_config_param_str("ap_ip", &ap_ip_str);
    if (ap_ip_str == NULL) {
        ap_ip_str = malloc(16);
        if (ap_ip_str != NULL) {
            strcpy(ap_ip_str, "192.168.4.1");
        }
    }

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
        safe_passwd == NULL || safe_ent_username == NULL || safe_ent_identity == NULL ||
        ap_ip_str == NULL) {
        ESP_LOGE(TAG, "Failed to escape HTML strings");
        free(safe_ap_ssid);
        free(safe_ap_passwd);
        free(safe_ssid);
        free(safe_passwd);
        free(safe_ent_username);
        free(safe_ent_identity);
        free(ap_ip_str);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Out of memory");
        return ESP_ERR_NO_MEM;
    }

    int page_len =
        strlen(config_page_template) +
        strlen(safe_ap_ssid) +
        strlen(safe_ap_passwd) +
        strlen(ap_ip_str) +
        strlen(ap_mac_str) +
        strlen(safe_ssid) +
        strlen(safe_passwd) +
        strlen(safe_ent_username) +
        strlen(safe_ent_identity) +
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
        free(ap_ip_str);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Out of memory");
        return ESP_ERR_NO_MEM;
    }

    snprintf(
        config_page, page_len, config_page_template,
        logout_section,
        safe_ap_ssid, safe_ap_passwd, ap_ip_str, ap_mac_str,
        safe_ssid, safe_passwd, safe_ent_username, safe_ent_identity, sta_mac_str,
        static_ip, subnet_mask, gateway_addr);

    free(safe_ap_ssid);
    free(safe_ap_passwd);
    free(safe_ssid);
    free(safe_passwd);
    free(safe_ent_username);
    free(safe_ent_identity);
    free(ap_ip_str);

    httpd_resp_send(req, config_page, strlen(config_page));
    free(config_page);

    return ESP_OK;
}

static httpd_uri_t configp = {
    .uri       = "/config",
    .method    = HTTP_GET,
    .handler   = config_get_handler,
};

/* Mappings page GET handler (DHCP Reservations + Port Forwarding) */
static esp_err_t mappings_get_handler(httpd_req_t *req)
{
    /* Check authentication if password protection is enabled */
    char password[64];
    bool password_protection_enabled = get_web_password(password, sizeof(password));

    if (password_protection_enabled && !is_authenticated(req)) {
        /* Redirect to index page with auth_required flag */
        httpd_resp_set_status(req, "303 See Other");
        httpd_resp_set_hdr(req, "Location", "/?auth_required=1");
        httpd_resp_send(req, NULL, 0);
        return ESP_OK;
    }

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

            /* Check for add DHCP reservation */
            if (httpd_query_key_value(buf, "dhcp_action", param1, sizeof(param1)) == ESP_OK) {
                if (strcmp(param1, "Add+Reservation") == 0 || strcmp(param1, "Add Reservation") == 0) {
                    if (httpd_query_key_value(buf, "dhcp_mac", param1, sizeof(param1)) == ESP_OK &&
                        httpd_query_key_value(buf, "dhcp_ip", param2, sizeof(param2)) == ESP_OK) {

                        preprocess_string(param1);
                        preprocess_string(param2);

                        // Parse MAC address
                        unsigned int mac[6];
                        if (sscanf(param1, "%02x:%02x:%02x:%02x:%02x:%02x",
                                   &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6 ||
                            sscanf(param1, "%02x-%02x-%02x-%02x-%02x-%02x",
                                   &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6) {

                            uint8_t mac_bytes[6];
                            for (int i = 0; i < 6; i++) {
                                mac_bytes[i] = (uint8_t)mac[i];
                            }

                            uint32_t ip = esp_ip4addr_aton(param2);
                            if (ip != 0) {
                                const char *name = NULL;
                                if (httpd_query_key_value(buf, "dhcp_name", param3, sizeof(param3)) == ESP_OK && strlen(param3) > 0) {
                                    preprocess_string(param3);
                                    name = param3;
                                }
                                add_dhcp_reservation(mac_bytes, ip, name);
                                ESP_LOGI(TAG, "Added DHCP reservation: %s -> %s", param1, param2);
                            }
                        }
                    }
                }
            }

            /* Check for delete DHCP reservation */
            if (httpd_query_key_value(buf, "del_dhcp_mac", param1, sizeof(param1)) == ESP_OK) {
                preprocess_string(param1);
                unsigned int mac[6];
                if (sscanf(param1, "%02X:%02X:%02X:%02X:%02X:%02X",
                           &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6 ||
                    sscanf(param1, "%02x:%02x:%02x:%02x:%02x:%02x",
                           &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6) {
                    uint8_t mac_bytes[6];
                    for (int i = 0; i < 6; i++) {
                        mac_bytes[i] = (uint8_t)mac[i];
                    }
                    del_dhcp_reservation(mac_bytes);
                    ESP_LOGI(TAG, "Deleted DHCP reservation: %s", param1);
                }
            }

            /* Check for add port mapping */
            if (httpd_query_key_value(buf, "port_action", param1, sizeof(param1)) == ESP_OK) {
                if (strcmp(param1, "Add+Forward") == 0 || strcmp(param1, "Add Forward") == 0) {
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

    /* Build connected clients table HTML */
    char clients_html[2048] = "";
    int clients_offset = 0;
    #define MAX_DISPLAYED_CLIENTS 8  // ESP32 AP supports max 8 stations
    connected_client_t clients[MAX_DISPLAYED_CLIENTS];
    int client_count = get_connected_clients(clients, MAX_DISPLAYED_CLIENTS);

    if (client_count > 0) {
        for (int i = 0; i < client_count; i++) {
            char ip_str[16] = "-";
            if (clients[i].has_ip) {
                esp_ip4_addr_t addr;
                addr.addr = clients[i].ip;
                snprintf(ip_str, sizeof(ip_str), IPSTR, IP2STR(&addr));
            }

            clients_offset += snprintf(clients_html + clients_offset, sizeof(clients_html) - clients_offset,
                "<tr>"
                "<td>%02X:%02X:%02X:%02X:%02X:%02X</td>"
                "<td>%s</td>"
                "<td>%s</td>"
                "</tr>",
                clients[i].mac[0], clients[i].mac[1],
                clients[i].mac[2], clients[i].mac[3],
                clients[i].mac[4], clients[i].mac[5],
                ip_str,
                clients[i].name[0] ? clients[i].name : "-"
            );
        }
    } else {
        snprintf(clients_html, sizeof(clients_html),
            "<tr><td colspan='3' style='text-align:center; color:#888;'>No clients connected</td></tr>");
    }

    /* Build DHCP reservations table HTML */
    char dhcp_html[2048] = "";
    int dhcp_offset = 0;
    bool has_reservations = false;

    for (int i = 0; i < MAX_DHCP_RESERVATIONS; i++) {
        if (dhcp_reservations[i].valid) {
            has_reservations = true;
            esp_ip4_addr_t addr;
            addr.addr = dhcp_reservations[i].ip;

            dhcp_offset += snprintf(dhcp_html + dhcp_offset, sizeof(dhcp_html) - dhcp_offset,
                "<tr>"
                "<td>%02X:%02X:%02X:%02X:%02X:%02X</td>"
                "<td>" IPSTR "</td>"
                "<td>%s</td>"
                "<td><a href='/mappings?del_dhcp_mac=%02X:%02X:%02X:%02X:%02X:%02X' class='red-button'>Delete</a></td>"
                "</tr>",
                dhcp_reservations[i].mac[0], dhcp_reservations[i].mac[1],
                dhcp_reservations[i].mac[2], dhcp_reservations[i].mac[3],
                dhcp_reservations[i].mac[4], dhcp_reservations[i].mac[5],
                IP2STR(&addr),
                dhcp_reservations[i].name[0] ? dhcp_reservations[i].name : "-",
                dhcp_reservations[i].mac[0], dhcp_reservations[i].mac[1],
                dhcp_reservations[i].mac[2], dhcp_reservations[i].mac[3],
                dhcp_reservations[i].mac[4], dhcp_reservations[i].mac[5]
            );
        }
    }

    if (!has_reservations) {
        snprintf(dhcp_html, sizeof(dhcp_html),
            "<tr><td colspan='4' style='text-align:center; color:#888;'>No DHCP reservations configured</td></tr>");
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
                "<td><a href='/mappings?del_proto=%s&del_port=%d' class='red-button'>Delete</a></td>"
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

    /* Check session status for logout button */
    bool session_active_for_logout = session_active && password_protection_enabled;
    char logout_section[256] = "";
    if (session_active_for_logout) {
        snprintf(logout_section, sizeof(logout_section),
                 "<a href='/?logout=1' style='padding: 0.4rem 1rem; background: rgba(255,82,82,0.15); color: #ff5252; border: 1px solid #ff5252; border-radius: 6px; text-decoration: none; font-size: 0.85rem; font-weight: 500;'>Logout</a>");
    }

    /* Build the page */
    const char* mappings_page_template = MAPPINGS_PAGE;
    int page_len = strlen(mappings_page_template) + strlen(clients_html) + strlen(dhcp_html) + strlen(portmap_html) + 512;
    char* mappings_page = malloc(page_len);

    if (mappings_page == NULL) {
        ESP_LOGE(TAG, "Failed to allocate memory for mappings page");
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Out of memory");
        return ESP_ERR_NO_MEM;
    }

    snprintf(mappings_page, page_len, mappings_page_template, logout_section, clients_html, dhcp_html, portmap_html);

    httpd_resp_send(req, mappings_page, strlen(mappings_page));
    free(mappings_page);

    return ESP_OK;
}

static httpd_uri_t mappingsp = {
    .uri       = "/mappings",
    .method    = HTTP_GET,
    .handler   = mappings_get_handler,
};

httpd_handle_t start_webserver(void)
{
    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.stack_size = 16384;  // Large stack needed for mappings page with 3x 2KB HTML buffers

    esp_timer_create(&restart_timer_args, &restart_timer);

    // Start the httpd server
    ESP_LOGI(TAG, "Starting server on port: '%d'", config.server_port);
    if (httpd_start(&server, &config) == ESP_OK) {
        // Set URI handlers
        ESP_LOGI(TAG, "Registering URI handlers");
        httpd_register_uri_handler(server, &indexp);
        httpd_register_uri_handler(server, &configp);
        httpd_register_uri_handler(server, &mappingsp);
        httpd_register_uri_handler(server, &favicon_uri);
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
