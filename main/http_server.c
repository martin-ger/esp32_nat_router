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
#include "pcap_capture.h"
#include "acl.h"
#include "remote_console.h"

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
                    ESP_LOGI(TAG, "Web UI login successful");
                    free(buf);
                    /* Redirect to reload page with session cookie */
                    httpd_resp_set_status(req, "303 See Other");
                    httpd_resp_set_hdr(req, "Location", "/");
                    httpd_resp_send(req, NULL, 0);
                    return ESP_OK;
                } else {
                    ESP_LOGW(TAG, "Web UI login failed: incorrect password");
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
                    ESP_LOGW(TAG, "Unauthorized attempt to change web password");
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

    /* Reusable buffer for building dynamic content */
    char row[512];

    /* --- Begin chunked response --- */
    httpd_resp_send_chunk(req, INDEX_CHUNK_HEAD, HTTPD_RESP_USE_STRLEN);

    /* Stream logout button if authenticated */
    if (authenticated) {
        httpd_resp_send_chunk(req,
            "<div style='text-align: right; margin-bottom: 0.5rem;'>"
            "<a href='/?logout=1' style='padding: 0.4rem 1rem; background: rgba(255,82,82,0.15); color: #ff5252; border: 1px solid #ff5252; border-radius: 6px; text-decoration: none; font-size: 0.85rem; font-weight: 500;'>Logout</a>"
            "</div>", HTTPD_RESP_USE_STRLEN);
    }

    /* Open status table */
    httpd_resp_send_chunk(req, INDEX_CHUNK_STATUS_OPEN, HTTPD_RESP_USE_STRLEN);

    /* Stream SSID row */
    char* safe_ap_ssid = html_escape(ap_ssid);
    if (safe_ap_ssid == NULL) safe_ap_ssid = strdup("(unknown)");
    snprintf(row, sizeof(row), "<tr><td>SSID:</td><td><strong>%s</strong></td></tr>", safe_ap_ssid);
    httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);
    free(safe_ap_ssid);

    /* Stream connection status row (with RSSI if connected) */
    if (ap_connect) {
        wifi_ap_record_t ap_info;
        if (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK) {
            snprintf(row, sizeof(row), "<tr><td>Connection:</td><td><strong>Connected (%d dBm)</strong></td></tr>", ap_info.rssi);
            httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);
        } else {
            httpd_resp_send_chunk(req, "<tr><td>Connection:</td><td><strong>Connected</strong></td></tr>", HTTPD_RESP_USE_STRLEN);
        }
    } else {
        httpd_resp_send_chunk(req, "<tr><td>Connection:</td><td><strong>Disconnected</strong></td></tr>", HTTPD_RESP_USE_STRLEN);
    }

    /* Stream uptime row */
    char uptime_str[32];
    format_uptime(get_uptime_seconds(), uptime_str, sizeof(uptime_str));
    snprintf(row, sizeof(row), "<tr><td>Uptime:</td><td>%s</td></tr>", uptime_str);
    httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);

    /* Stream STA IP row */
    if (ap_connect) {
        esp_ip4_addr_t addr;
        addr.addr = my_ip;
        snprintf(row, sizeof(row), "<tr><td>STA IP:</td><td>" IPSTR "</td></tr>", IP2STR(&addr));
    } else {
        snprintf(row, sizeof(row), "<tr><td>STA IP:</td><td>N/A</td></tr>");
    }
    httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);

    /* Stream AP IP row */
    esp_ip4_addr_t ap_addr;
    ap_addr.addr = my_ap_ip;
    snprintf(row, sizeof(row), "<tr><td>AP IP:</td><td>" IPSTR "</td></tr>", IP2STR(&ap_addr));
    httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);

    /* Stream DHCP Pool row */
    uint32_t start_ip, end_ip;
    get_dhcp_pool_range(my_ap_ip, &start_ip, &end_ip);
    esp_ip4_addr_t start_addr, end_addr;
    start_addr.addr = start_ip;
    end_addr.addr = end_ip;
    snprintf(row, sizeof(row), "<tr><td>DHCP Pool:</td><td>" IPSTR " - " IPSTR "</td></tr>",
             IP2STR(&start_addr), IP2STR(&end_addr));
    httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);

    /* Stream Clients row */
    resync_connect_count();
    snprintf(row, sizeof(row), "<tr><td>Clients:</td><td>%d</td></tr>", connect_count);
    httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);

    /* Stream Bytes Sent row */
    uint64_t bytes_sent = get_sta_bytes_sent();
    float sent_mb = bytes_sent / (1024.0 * 1024.0);
    snprintf(row, sizeof(row), "<tr><td>Bytes Sent:</td><td>%.1f MB</td></tr>", sent_mb);
    httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);

    /* Stream Bytes Received row */
    uint64_t bytes_received = get_sta_bytes_received();
    float received_mb = bytes_received / (1024.0 * 1024.0);
    snprintf(row, sizeof(row), "<tr><td>Bytes Received:</td><td>%.1f MB</td></tr>", received_mb);
    httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);

    /* Stream PCAP status row */
    pcap_capture_mode_t mode = pcap_get_mode();
    if (mode != PCAP_MODE_OFF) {
        const char* mode_name = (mode == PCAP_MODE_ACL_MONITOR) ? "ACL Monitor" : "Promiscuous";
        snprintf(row, sizeof(row),
                 "<tr><td>PCAP Capture:</td><td><span style='color: #4caf50;'>%s</span> <br>captured: %lu, dropped: %lu</td></tr>",
                 mode_name,
                 (unsigned long)pcap_get_captured_count(),
                 (unsigned long)pcap_get_dropped_count());
    } else {
        snprintf(row, sizeof(row), "<tr><td>PCAP Capture:</td><td><span style='color: #888;'>Off</span></td></tr>");
    }
    httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);

    /* Close status table */
    httpd_resp_send_chunk(req, INDEX_CHUNK_STATUS_CLOSE, HTTPD_RESP_USE_STRLEN);

    /* Navigation buttons */
    httpd_resp_send_chunk(req, INDEX_CHUNK_BUTTONS, HTTPD_RESP_USE_STRLEN);

    /* --- Auth UI Section (streamed directly) --- */

    /* Show message if any */
    if (login_message[0] != '\0') {
        const char* msg_style;
        if (strstr(login_message, "ERROR") != NULL) {
            msg_style = "background: #ffebee; color: #c62828; border: 2px solid #ef5350";
        } else {
            msg_style = "background: #e8f5e9; color: #2e7d32; border: 2px solid #66bb6a";
        }
        snprintf(row, sizeof(row),
                 "<div style='margin-top: 1.5rem; padding: 1rem; %s; border-radius: 8px; font-size: 0.95rem;'>%s</div>",
                 msg_style, login_message);
        httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);
    }

    /* Show warning if no password protection */
    if (!password_protection_enabled) {
        httpd_resp_send_chunk(req,
            "<div style='margin-top: 1.5rem; padding: 1rem; background: #fff3cd; border: 2px solid #ffa726; border-radius: 8px;'>"
            "<strong style='color: #f57c00;'>⚠ No Password Protection</strong>"
            "<p style='margin-top: 0.5rem; color: #666; font-size: 0.9rem;'>Anyone on this network can access router settings. Set a password below.</p>"
            "</div>", HTTPD_RESP_USE_STRLEN);
    }

    /* Show login form if password is set and not authenticated */
    if (password_protection_enabled && !authenticated) {
        httpd_resp_send_chunk(req,
            "<div style='margin-top: 1.5rem; padding: 1.5rem; background: rgba(22, 33, 62, 0.6); border: 1px solid rgba(0, 217, 255, 0.2); border-radius: 12px;'>"
            "<h2 style='margin-top: 0; margin-bottom: 1rem; color: #00d9ff; font-size: 1.1rem;'>🔒 Login Required</h2>"
            "<form action='' method='GET'>"
            "<input type='password' name='login_password' placeholder='Enter password' style='width: 100%; padding: 0.75rem; margin-bottom: 0.75rem; background: rgba(255,255,255,0.1); border: 1px solid rgba(0,217,255,0.3); border-radius: 8px; color: #e0e0e0; font-size: 1rem;'/>"
            "<input type='submit' value='Login' style='width: 100%; padding: 0.75rem; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #fff; border: none; border-radius: 8px; font-size: 1rem; font-weight: 600; cursor: pointer;'/>"
            "</form>"
            "</div>", HTTPD_RESP_USE_STRLEN);
    }

    /* Show password management form if authenticated or no password set */
    if (authenticated || !password_protection_enabled) {
        const char* form_title = password_protection_enabled ? "Change Password" : "Set Password";
        httpd_resp_send_chunk(req,
            "<div style='margin-top: 1.5rem; padding: 1.5rem; background: rgba(22, 33, 62, 0.6); border: 1px solid rgba(0, 217, 255, 0.2); border-radius: 12px;'>"
            "<h2 style='margin-top: 0; margin-bottom: 1rem; color: #00d9ff; font-size: 1.1rem;'>🔑 ", HTTPD_RESP_USE_STRLEN);
        httpd_resp_send_chunk(req, form_title, HTTPD_RESP_USE_STRLEN);
        httpd_resp_send_chunk(req,
            "</h2>"
            "<form action='' method='GET'>"
            "<input type='password' name='new_password' placeholder='New password (empty to disable)' style='width: 100%; padding: 0.75rem; margin-bottom: 0.75rem; background: rgba(255,255,255,0.1); border: 1px solid rgba(0,217,255,0.3); border-radius: 8px; color: #e0e0e0; font-size: 1rem;'/>"
            "<input type='password' name='confirm_password' placeholder='Confirm password' style='width: 100%; padding: 0.75rem; margin-bottom: 0.75rem; background: rgba(255,255,255,0.1); border: 1px solid rgba(0,217,255,0.3); border-radius: 8px; color: #e0e0e0; font-size: 1rem;'/>"
            "<input type='submit' value='", HTTPD_RESP_USE_STRLEN);
        httpd_resp_send_chunk(req, form_title, HTTPD_RESP_USE_STRLEN);
        httpd_resp_send_chunk(req,
            "' style='width: 100%; padding: 0.75rem; background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); color: #fff; border: none; border-radius: 8px; font-size: 1rem; font-weight: 600; cursor: pointer;'/>"
            "<p style='margin-top: 0.75rem; color: #888; font-size: 0.85rem;'>Leave empty to disable password protection.</p>"
            "</form>"
            "</div>", HTTPD_RESP_USE_STRLEN);
    }

    /* Footer */
    httpd_resp_send_chunk(req, INDEX_CHUNK_TAIL, HTTPD_RESP_USE_STRLEN);

    /* End chunked response */
    httpd_resp_send_chunk(req, NULL, 0);

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
        ESP_LOGW(TAG, "Unauthenticated access attempt to /config");
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
            char reset_param[16];
            if (httpd_query_key_value(buf, "reset", reset_param, sizeof(reset_param)) == ESP_OK) {
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
                    preprocess_string(param2);

                    // "Open network" checkbox overrides password to empty
                    {
                        char open_val[4] = "";
                        if (httpd_query_key_value(buf, "ap_open", open_val, sizeof(open_val)) == ESP_OK) {
                            param2[0] = '\0';
                        } else if (strlen(param2) == 0) {
                            // Keep existing password if field was left empty
                            strlcpy(param2, ap_passwd, sizeof(param2));
                        }
                    }

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

                    // Handle AP hidden SSID setting
                    // Checkbox sends value only when checked, so absence means "off"
                    {
                        nvs_handle_t nvs;
                        if (nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs) == ESP_OK) {
                            int hidden_val = 0;
                            if (httpd_query_key_value(buf, "ap_hidden", param5, sizeof(param5)) == ESP_OK) {
                                hidden_val = 1;
                                ESP_LOGI(TAG, "Found URL query parameter => ap_hidden=%s", param5);
                            }
                            nvs_set_i32(nvs, "ap_hidden", hidden_val);
                            nvs_commit(nvs);
                            nvs_close(nvs);
                            ap_ssid_hidden = (uint8_t)hidden_val;
                            ESP_LOGI(TAG, "AP hidden SSID set to: %d", hidden_val);
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
                    preprocess_string(param2);

                    // Keep existing password if field was left empty
                    if (strlen(param2) == 0) {
                        strlcpy(param2, passwd, sizeof(param2));
                    }
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

                            // Save WPA2-Enterprise settings to NVS
                            {
                                nvs_handle_t nvs;
                                if (nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs) == ESP_OK) {
                                    char eap_param[4] = "";
                                    int eap_val = 0;
                                    if (httpd_query_key_value(buf, "eap_method", eap_param, sizeof(eap_param)) == ESP_OK) {
                                        eap_val = atoi(eap_param);
                                    }
                                    nvs_set_i32(nvs, "eap_method", eap_val);
                                    eap_method = eap_val;

                                    char phase2_param[4] = "";
                                    int phase2_val = 0;
                                    if (httpd_query_key_value(buf, "ttls_phase2", phase2_param, sizeof(phase2_param)) == ESP_OK) {
                                        phase2_val = atoi(phase2_param);
                                    }
                                    nvs_set_i32(nvs, "ttls_phase2", phase2_val);
                                    ttls_phase2 = phase2_val;

                                    // Checkboxes: present = 1, absent = 0
                                    char cb_param[4] = "";
                                    int cb_val = 0;
                                    if (httpd_query_key_value(buf, "cert_bundle", cb_param, sizeof(cb_param)) == ESP_OK) {
                                        cb_val = 1;
                                    }
                                    nvs_set_i32(nvs, "cert_bundle", cb_val);
                                    use_cert_bundle = cb_val;

                                    int tc_val = 0;
                                    if (httpd_query_key_value(buf, "no_time_chk", cb_param, sizeof(cb_param)) == ESP_OK) {
                                        tc_val = 1;
                                    }
                                    nvs_set_i32(nvs, "no_time_chk", tc_val);
                                    disable_time_check = tc_val;

                                    nvs_commit(nvs);
                                    nvs_close(nvs);
                                }
                            }

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

            /* Handle Remote Console enable/disable */
            if (httpd_query_key_value(buf, "rc_enabled", param1, sizeof(param1)) == ESP_OK) {
                preprocess_string(param1);
                if (strcmp(param1, "1") == 0) {
                    remote_console_enable();
                    ESP_LOGI(TAG, "Remote console enabled via web");
                } else {
                    remote_console_disable();
                    ESP_LOGI(TAG, "Remote console disabled via web");
                }
                free(buf);
                httpd_resp_set_status(req, "303 See Other");
                httpd_resp_set_hdr(req, "Location", "/config");
                httpd_resp_send(req, NULL, 0);
                return ESP_OK;
            }

            /* Handle Remote Console port */
            if (httpd_query_key_value(buf, "rc_port", param1, sizeof(param1)) == ESP_OK) {
                preprocess_string(param1);
                int port = atoi(param1);
                if (port >= 1 && port <= 65535) {
                    remote_console_set_port((uint16_t)port);
                    ESP_LOGI(TAG, "Remote console port set to %d via web", port);
                }
                free(buf);
                httpd_resp_set_status(req, "303 See Other");
                httpd_resp_set_hdr(req, "Location", "/config");
                httpd_resp_send(req, NULL, 0);
                return ESP_OK;
            }

            /* Handle Remote Console bind */
            if (httpd_query_key_value(buf, "rc_bind", param1, sizeof(param1)) == ESP_OK) {
                preprocess_string(param1);
                int bind = atoi(param1);
                if (bind >= 0 && bind <= 2) {
                    remote_console_set_bind((remote_console_bind_t)bind);
                    ESP_LOGI(TAG, "Remote console bind set to %d via web", bind);
                }
                free(buf);
                httpd_resp_set_status(req, "303 See Other");
                httpd_resp_set_hdr(req, "Location", "/config");
                httpd_resp_send(req, NULL, 0);
                return ESP_OK;
            }

            /* Handle Remote Console timeout */
            if (httpd_query_key_value(buf, "rc_timeout", param1, sizeof(param1)) == ESP_OK) {
                preprocess_string(param1);
                int timeout = atoi(param1);
                if (timeout >= 0) {
                    remote_console_set_timeout((uint32_t)timeout);
                    ESP_LOGI(TAG, "Remote console timeout set to %d via web", timeout);
                }
                free(buf);
                httpd_resp_set_status(req, "303 See Other");
                httpd_resp_set_hdr(req, "Location", "/config");
                httpd_resp_send(req, NULL, 0);
                return ESP_OK;
            }

            /* Handle Remote Console kick */
            if (httpd_query_key_value(buf, "rc_kick", param1, sizeof(param1)) == ESP_OK) {
                remote_console_kick();
                ESP_LOGI(TAG, "Remote console session kicked via web");
                free(buf);
                httpd_resp_set_status(req, "303 See Other");
                httpd_resp_set_hdr(req, "Location", "/config");
                httpd_resp_send(req, NULL, 0);
                return ESP_OK;
            }

            /* Handle PCAP mode selection */
            if (httpd_query_key_value(buf, "pcap_mode", param1, sizeof(param1)) == ESP_OK) {
                preprocess_string(param1);
                if (strcmp(param1, "off") == 0) {
                    pcap_set_mode(PCAP_MODE_OFF);
                    ESP_LOGI(TAG, "PCAP mode set to OFF via web");
                } else if (strcmp(param1, "acl") == 0) {
                    pcap_set_mode(PCAP_MODE_ACL_MONITOR);
                    ESP_LOGI(TAG, "PCAP mode set to ACL_MONITOR via web");
                } else if (strcmp(param1, "promisc") == 0) {
                    pcap_set_mode(PCAP_MODE_PROMISCUOUS);
                    ESP_LOGI(TAG, "PCAP mode set to PROMISCUOUS via web");
                }
                free(buf);
                httpd_resp_set_status(req, "303 See Other");
                httpd_resp_set_hdr(req, "Location", "/config");
                httpd_resp_send(req, NULL, 0);
                return ESP_OK;
            }

            /* Handle PCAP snaplen */
            if (httpd_query_key_value(buf, "pcap_snaplen", param1, sizeof(param1)) == ESP_OK) {
                preprocess_string(param1);
                int snaplen = atoi(param1);
                if (snaplen >= 64 && snaplen <= 1600) {
                    pcap_set_snaplen((uint16_t)snaplen);
                    ESP_LOGI(TAG, "PCAP snaplen set to %d via web", snaplen);
                }
                free(buf);
                httpd_resp_set_status(req, "303 See Other");
                httpd_resp_set_hdr(req, "Location", "/config");
                httpd_resp_send(req, NULL, 0);
                return ESP_OK;
            }
        }
        free(buf);
    }

    /* Check for SSID pre-fill from scan page */
    char prefill_ssid[64] = "";
    buf_len = httpd_req_get_url_query_len(req) + 1;
    if (buf_len > 1) {
        buf = malloc(buf_len);
        if (buf != NULL && httpd_req_get_url_query_str(req, buf, buf_len) == ESP_OK) {
            if (httpd_query_key_value(buf, "ssid", prefill_ssid, sizeof(prefill_ssid)) == ESP_OK) {
                preprocess_string(prefill_ssid);
                ESP_LOGI(TAG, "Pre-filling SSID from scan: %s", prefill_ssid);
            }
        }
        if (buf) free(buf);
    }

    /* Escape values for HTML */
    char* safe_ap_ssid = html_escape(ap_ssid);
    char* safe_ssid = html_escape(prefill_ssid[0] ? prefill_ssid : ssid);
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

    // Check if any html_escape failed
    if (safe_ap_ssid == NULL || safe_ssid == NULL ||
        safe_ent_username == NULL || safe_ent_identity == NULL ||
        ap_ip_str == NULL) {
        ESP_LOGE(TAG, "Failed to escape HTML strings");
        free(safe_ap_ssid);
        free(safe_ssid);
        free(safe_ent_username);
        free(safe_ent_identity);
        free(ap_ip_str);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Out of memory");
        return ESP_ERR_NO_MEM;
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

    // Remote Console state
    remote_console_config_t rc_config;
    remote_console_status_t rc_status;
    remote_console_get_config(&rc_config);
    remote_console_get_status(&rc_status);

    const char* ap_open_checked = (strlen(ap_passwd) == 0) ? "checked" : "";
    const char* ap_hidden_checked = ap_ssid_hidden ? "checked" : "";
    const char* rc_enabled_checked = rc_config.enabled ? "checked" : "";
    const char* rc_disabled_checked = rc_config.enabled ? "" : "checked";

    const char* rc_status_color;
    const char* rc_status_text;
    const char* rc_kick_section = "";
    char rc_kick_buf[200] = "";

    switch (rc_status.state) {
        case RC_STATE_DISABLED:
            rc_status_color = "#888";
            rc_status_text = "Disabled";
            break;
        case RC_STATE_LISTENING:
            rc_status_color = "#4caf50";
            rc_status_text = "Listening";
            break;
        case RC_STATE_AUTH_WAIT:
            rc_status_color = "#ffc107";
            rc_status_text = "Authenticating...";
            break;
        case RC_STATE_ACTIVE:
            rc_status_color = "#00d9ff";
            rc_status_text = rc_status.client_ip;
            snprintf(rc_kick_buf, sizeof(rc_kick_buf),
                " <a href='/config?rc_kick=1' style='margin-left: 0.5rem; padding: 0.2rem 0.6rem; background: #f44336; color: #fff; border-radius: 4px; text-decoration: none; font-size: 0.8rem;'>Kick</a>");
            rc_kick_section = rc_kick_buf;
            break;
        default:
            rc_status_color = "#888";
            rc_status_text = "Unknown";
            break;
    }

    const char* rc_bind_both_sel = (rc_config.bind == RC_BIND_BOTH) ? "selected" : "";
    const char* rc_bind_ap_sel = (rc_config.bind == RC_BIND_AP_ONLY) ? "selected" : "";
    const char* rc_bind_sta_sel = (rc_config.bind == RC_BIND_STA_ONLY) ? "selected" : "";

    // PCAP state
    pcap_capture_mode_t pcap_mode = pcap_get_mode();
    const char* pcap_mode_off_sel = (pcap_mode == PCAP_MODE_OFF) ? "selected" : "";
    const char* pcap_mode_acl_sel = (pcap_mode == PCAP_MODE_ACL_MONITOR) ? "selected" : "";
    const char* pcap_mode_promisc_sel = (pcap_mode == PCAP_MODE_PROMISCUOUS) ? "selected" : "";
    bool pcap_client = pcap_client_connected();
    const char* pcap_client_color = pcap_client ? "#4caf50" : "#888";
    const char* pcap_client_text = pcap_client ? "Connected" : "Not connected";
    uint32_t pcap_captured = pcap_get_captured_count();
    uint32_t pcap_dropped = pcap_get_dropped_count();
    int current_snaplen = pcap_get_snaplen();

    /* Reusable buffer for building sections */
    char section[2048];

    /* --- Begin chunked response --- */

    /* Chunk 1: Page header (styles) */
    httpd_resp_send_chunk(req, CONFIG_CHUNK_HEAD, HTTPD_RESP_USE_STRLEN);

    /* Chunk 2: Logout button (if authenticated) */
    if (session_active && password_protection_enabled) {
        httpd_resp_send_chunk(req,
            "<a href='/?logout=1' style='padding: 0.4rem 1rem; background: rgba(255,82,82,0.15); color: #ff5252; border: 1px solid #ff5252; border-radius: 6px; text-decoration: none; font-size: 0.85rem; font-weight: 500;'>Logout</a>",
            HTTPD_RESP_USE_STRLEN);
    }

    /* Chunk 3: JavaScript */
    httpd_resp_send_chunk(req, CONFIG_CHUNK_SCRIPT, HTTPD_RESP_USE_STRLEN);

    /* Chunk 4: AP Settings */
    snprintf(section, sizeof(section), CONFIG_CHUNK_AP,
        safe_ap_ssid, ap_ip_str, ap_mac_str, ap_open_checked, ap_hidden_checked);
    httpd_resp_send_chunk(req, section, HTTPD_RESP_USE_STRLEN);

    /* Chunk 5: STA Settings */
    snprintf(section, sizeof(section), CONFIG_CHUNK_STA,
        safe_ssid, safe_ent_username, safe_ent_identity,
        eap_method == 0 ? "selected" : "", eap_method == 1 ? "selected" : "",
        eap_method == 2 ? "selected" : "", eap_method == 3 ? "selected" : "",
        ttls_phase2 == 0 ? "selected" : "", ttls_phase2 == 1 ? "selected" : "",
        ttls_phase2 == 2 ? "selected" : "", ttls_phase2 == 3 ? "selected" : "",
        use_cert_bundle ? "checked" : "", disable_time_check ? "checked" : "",
        sta_mac_str);
    httpd_resp_send_chunk(req, section, HTTPD_RESP_USE_STRLEN);

    /* Chunk 6: Static IP Settings */
    snprintf(section, sizeof(section), CONFIG_CHUNK_STATIC,
        static_ip, subnet_mask, gateway_addr);
    httpd_resp_send_chunk(req, section, HTTPD_RESP_USE_STRLEN);

    /* Chunk 7: Remote Console */
    snprintf(section, sizeof(section), CONFIG_CHUNK_RC,
        rc_enabled_checked, rc_disabled_checked,
        rc_status_color, rc_status_text, rc_kick_section,
        rc_config.port,
        rc_bind_both_sel, rc_bind_ap_sel, rc_bind_sta_sel,
        (unsigned long)rc_config.idle_timeout_sec);
    httpd_resp_send_chunk(req, section, HTTPD_RESP_USE_STRLEN);

    /* Chunk 8: PCAP */
    char sta_ip_str[16];
    {
        ip4_addr_t sta_addr;
        sta_addr.addr = my_ip;
        snprintf(sta_ip_str, sizeof(sta_ip_str), IPSTR, IP2STR(&sta_addr));
    }
    snprintf(section, sizeof(section), CONFIG_CHUNK_PCAP,
        pcap_mode_off_sel, pcap_mode_acl_sel, pcap_mode_promisc_sel,
        pcap_client_color, pcap_client_text,
        (unsigned long)pcap_captured, (unsigned long)pcap_dropped,
        current_snaplen, sta_ip_str);
    httpd_resp_send_chunk(req, section, HTTPD_RESP_USE_STRLEN);

    /* Chunk 9: Device management and footer */
    httpd_resp_send_chunk(req, CONFIG_CHUNK_TAIL, HTTPD_RESP_USE_STRLEN);

    /* End chunked response */
    httpd_resp_send_chunk(req, NULL, 0);

    /* Cleanup */
    free(safe_ap_ssid);
    free(safe_ssid);
    free(safe_ent_username);
    free(safe_ent_identity);
    free(ap_ip_str);

    return ESP_OK;
}

static httpd_uri_t configp = {
    .uri       = "/config",
    .method    = HTTP_GET,
    .handler   = config_get_handler,
};

/* Mappings page GET handler (DHCP Reservations + Port Forwarding) - Chunked transfer */
static esp_err_t mappings_get_handler(httpd_req_t *req)
{
    /* Check authentication if password protection is enabled */
    char password[64];
    bool password_protection_enabled = get_web_password(password, sizeof(password));

    if (password_protection_enabled && !is_authenticated(req)) {
        ESP_LOGW(TAG, "Unauthenticated access attempt to /mappings");
        /* Redirect to index page with auth_required flag */
        httpd_resp_set_status(req, "303 See Other");
        httpd_resp_set_hdr(req, "Location", "/?auth_required=1");
        httpd_resp_send(req, NULL, 0);
        return ESP_OK;
    }

    char* buf;
    size_t buf_len;
    char error_msg[128] = "";

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

            /* Check for error parameter first */
            if (httpd_query_key_value(buf, "error", param1, sizeof(param1)) == ESP_OK) {
                /* Decode + back to spaces */
                for (char *p = param1; *p; p++) {
                    if (*p == '+') *p = ' ';
                }
                snprintf(error_msg, sizeof(error_msg), "%s", param1);
            }

            /* Check for add DHCP reservation */
            if (httpd_query_key_value(buf, "dhcp_action", param1, sizeof(param1)) == ESP_OK) {
                if (strcmp(param1, "Add+Reservation") == 0 || strcmp(param1, "Add Reservation") == 0) {
                    if (httpd_query_key_value(buf, "dhcp_mac", param1, sizeof(param1)) == ESP_OK &&
                        httpd_query_key_value(buf, "dhcp_ip", param2, sizeof(param2)) == ESP_OK) {

                        preprocess_string(param1);
                        preprocess_string(param2);

                        const char *err_msg = NULL;

                        // Parse MAC address
                        unsigned int mac[6];
                        uint8_t mac_bytes[6];
                        if (sscanf(param1, "%02x:%02x:%02x:%02x:%02x:%02x",
                                   &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6 &&
                            sscanf(param1, "%02x-%02x-%02x-%02x-%02x-%02x",
                                   &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6) {
                            err_msg = "Invalid MAC address format";
                        } else {
                            for (int i = 0; i < 6; i++) {
                                mac_bytes[i] = (uint8_t)mac[i];
                            }

                            uint32_t ip = esp_ip4addr_aton(param2);
                            if (ip == IPADDR_NONE) {
                                err_msg = "Invalid IP address";
                            } else if ((ip & 0x00FFFFFF) != (my_ap_ip & 0x00FFFFFF)) {
                                err_msg = "IP must be in the same network as the AP";
                            } else {
                                const char *name = NULL;
                                if (httpd_query_key_value(buf, "dhcp_name", param3, sizeof(param3)) == ESP_OK && strlen(param3) > 0) {
                                    preprocess_string(param3);
                                    name = param3;
                                }
                                add_dhcp_reservation(mac_bytes, ip, name);
                                ESP_LOGI(TAG, "Added DHCP reservation: %s -> %s", param1, param2);
                            }
                        }

                        if (err_msg != NULL) {
                            /* Redirect back with error parameter */
                            char redirect_url[128];
                            snprintf(redirect_url, sizeof(redirect_url), "/mappings?error=%s", err_msg);
                            for (char *p = redirect_url; *p; p++) {
                                if (*p == ' ') *p = '+';
                            }
                            httpd_resp_set_status(req, "303 See Other");
                            httpd_resp_set_hdr(req, "Location", redirect_url);
                            httpd_resp_send(req, NULL, 0);
                            free(buf);
                            return ESP_OK;
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

                        preprocess_string(param3);
                        uint8_t proto = (strcmp(param1, "TCP") == 0) ? PROTO_TCP : PROTO_UDP;
                        uint16_t ext_port = atoi(param2);
                        uint32_t int_ip = esp_ip4addr_aton(param3);

                        /* If IP parsing failed, try resolving as device name */
                        if (int_ip == IPADDR_NONE) {
                            if (!resolve_device_name_to_ip(param3, &int_ip)) {
                                ESP_LOGW(TAG, "Invalid IP or device name: %s", param3);
                            }
                        }
                        uint16_t int_port = atoi(param4);

                        /* Validate internal IP is in same /24 network as AP interface */
                        const char *err_msg = NULL;
                        if (int_ip == IPADDR_NONE) {
                            err_msg = "Invalid IP address or device name";
                        } else if ((int_ip & 0x00FFFFFF) != (my_ap_ip & 0x00FFFFFF)) {
                            esp_ip4_addr_t ap_addr;
                            ap_addr.addr = my_ap_ip;
                            ESP_LOGW(TAG, "Internal IP not in AP network (" IPSTR "/24)", IP2STR(&ap_addr));
                            err_msg = "Internal IP must be in the same network as the AP";
                        } else {
                            /* Check if external port is already in use for this protocol */
                            for (int i = 0; i < IP_PORTMAP_MAX; i++) {
                                if (portmap_tab[i].valid &&
                                    portmap_tab[i].proto == proto &&
                                    portmap_tab[i].mport == ext_port) {
                                    ESP_LOGW(TAG, "External port %d already mapped", ext_port);
                                    err_msg = "External port is already in use";
                                    break;
                                }
                            }
                        }

                        if (err_msg == NULL) {
                            add_portmap(proto, ext_port, int_ip, int_port);
                            ESP_LOGI(TAG, "Added port mapping: %s %d -> %s:%d", param1, ext_port, param3, int_port);
                        } else {
                            /* Redirect back with error parameter */
                            char redirect_url[128];
                            snprintf(redirect_url, sizeof(redirect_url), "/mappings?error=%s", err_msg);
                            /* URL encode spaces */
                            for (char *p = redirect_url; *p; p++) {
                                if (*p == ' ') *p = '+';
                            }
                            httpd_resp_set_status(req, "303 See Other");
                            httpd_resp_set_hdr(req, "Location", redirect_url);
                            httpd_resp_send(req, NULL, 0);
                            free(buf);
                            return ESP_OK;
                        }
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

    /* Reusable buffer for building individual rows */
    char row[384];

    /* --- Begin chunked response --- */

    /* Chunk 1: Page header (styles, scripts) */
    httpd_resp_send_chunk(req, MAPPINGS_CHUNK_HEAD, HTTPD_RESP_USE_STRLEN);

    /* Chunk 2: Error modal (if any) */
    if (error_msg[0] != '\0') {
        snprintf(row, sizeof(row),
            "<div class='modal-overlay show' id='errorModal'>"
            "<div class='modal-box'>"
            "<h3>Error</h3>"
            "<p>%s</p>"
            "<button onclick=\"document.getElementById('errorModal').classList.remove('show'); history.replaceState(null, '', '/mappings');\">OK</button>"
            "</div>"
            "</div>",
            error_msg);
        httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);
    }

    /* Chunk 3: Container start and header */
    httpd_resp_send_chunk(req, MAPPINGS_CHUNK_MID1, HTTPD_RESP_USE_STRLEN);

    /* Chunk 4: Logout button (if authenticated) */
    if (session_active && password_protection_enabled) {
        httpd_resp_send_chunk(req,
            "<a href='/?logout=1' style='padding: 0.4rem 1rem; background: rgba(255,82,82,0.15); color: #ff5252; border: 1px solid #ff5252; border-radius: 6px; text-decoration: none; font-size: 0.85rem; font-weight: 500;'>Logout</a>",
            HTTPD_RESP_USE_STRLEN);
    }

    /* Chunk 5: Connected clients table header */
    httpd_resp_send_chunk(req, MAPPINGS_CHUNK_MID2, HTTPD_RESP_USE_STRLEN);

    /* Chunk 6: Stream connected clients rows */
    #define MAX_DISPLAYED_CLIENTS 8
    connected_client_t clients[MAX_DISPLAYED_CLIENTS];
    int client_count = get_connected_clients(clients, MAX_DISPLAYED_CLIENTS);
    connect_count = client_count;

    if (client_count > 0) {
        for (int i = 0; i < client_count; i++) {
            char ip_str[16] = "-";
            if (clients[i].has_ip) {
                esp_ip4_addr_t addr;
                addr.addr = clients[i].ip;
                snprintf(ip_str, sizeof(ip_str), IPSTR, IP2STR(&addr));
            }

            char mac_str[18];
            snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                clients[i].mac[0], clients[i].mac[1],
                clients[i].mac[2], clients[i].mac[3],
                clients[i].mac[4], clients[i].mac[5]);

            /* Escape single quotes in name for JavaScript */
            char js_name[DHCP_RESERVATION_NAME_LEN * 2];
            const char *src_name = clients[i].name[0] ? clients[i].name : "";
            int j = 0;
            for (int k = 0; src_name[k] && j < (int)sizeof(js_name) - 2; k++) {
                if (src_name[k] == '\'') {
                    js_name[j++] = '\\';
                }
                js_name[j++] = src_name[k];
            }
            js_name[j] = '\0';

            snprintf(row, sizeof(row),
                "<tr>"
                "<td>%s</td>"
                "<td>%s</td>"
                "<td>%s</td>"
                "<td><button type='button' class='green-button' onclick=\"fillDhcpForm('%s','%s','%s')\">Reserve</button></td>"
                "</tr>",
                mac_str,
                ip_str,
                clients[i].name[0] ? clients[i].name : "-",
                mac_str,
                clients[i].has_ip ? ip_str : "",
                js_name
            );
            httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);
        }
    } else {
        httpd_resp_send_chunk(req,
            "<tr><td colspan='4' style='text-align:center; color:#888;'>No clients connected</td></tr>",
            HTTPD_RESP_USE_STRLEN);
    }

    /* Chunk 7: DHCP reservations table header */
    httpd_resp_send_chunk(req, MAPPINGS_CHUNK_MID3, HTTPD_RESP_USE_STRLEN);

    /* Chunk 8: Stream DHCP reservation rows */
    bool has_reservations = false;
    for (int i = 0; i < MAX_DHCP_RESERVATIONS; i++) {
        if (dhcp_reservations[i].valid) {
            has_reservations = true;
            esp_ip4_addr_t addr;
            addr.addr = dhcp_reservations[i].ip;

            snprintf(row, sizeof(row),
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
            httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);
        }
    }

    if (!has_reservations) {
        httpd_resp_send_chunk(req,
            "<tr><td colspan='4' style='text-align:center; color:#888;'>No DHCP reservations configured</td></tr>",
            HTTPD_RESP_USE_STRLEN);
    }

    /* Chunk 9: DHCP form and port forwarding table header */
    httpd_resp_send_chunk(req, MAPPINGS_CHUNK_MID4, HTTPD_RESP_USE_STRLEN);

    /* Chunk 10: Stream port mapping rows */
    bool has_mappings = false;
    for (int i = 0; i < IP_PORTMAP_MAX; i++) {
        if (portmap_tab[i].valid) {
            has_mappings = true;

            /* Try to look up device name for destination IP */
            const char *name = lookup_device_name_by_ip(portmap_tab[i].daddr);
            char ip_or_name[DHCP_RESERVATION_NAME_LEN];
            if (name) {
                snprintf(ip_or_name, sizeof(ip_or_name), "%s", name);
            } else {
                esp_ip4_addr_t addr;
                addr.addr = portmap_tab[i].daddr;
                snprintf(ip_or_name, sizeof(ip_or_name), IPSTR, IP2STR(&addr));
            }

            snprintf(row, sizeof(row),
                "<tr>"
                "<td>%s</td>"
                "<td>%d</td>"
                "<td>%s</td>"
                "<td>%d</td>"
                "<td><a href='/mappings?del_proto=%s&del_port=%d' class='red-button'>Delete</a></td>"
                "</tr>",
                portmap_tab[i].proto == PROTO_TCP ? "TCP" : "UDP",
                portmap_tab[i].mport,
                ip_or_name,
                portmap_tab[i].dport,
                portmap_tab[i].proto == PROTO_TCP ? "TCP" : "UDP",
                portmap_tab[i].mport
            );
            httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);
        }
    }

    if (!has_mappings) {
        httpd_resp_send_chunk(req,
            "<tr><td colspan='5' style='text-align:center; color:#888;'>No port mappings configured</td></tr>",
            HTTPD_RESP_USE_STRLEN);
    }

    /* Chunk 11: Page tail (port form, footer) */
    httpd_resp_send_chunk(req, MAPPINGS_CHUNK_TAIL, HTTPD_RESP_USE_STRLEN);

    /* End chunked response */
    httpd_resp_send_chunk(req, NULL, 0);

    return ESP_OK;
}

static httpd_uri_t mappingsp = {
    .uri       = "/mappings",
    .method    = HTTP_GET,
    .handler   = mappings_get_handler,
};

/* Firewall (ACL) page GET handler */
static esp_err_t firewall_get_handler(httpd_req_t *req)
{
    /* Check authentication if password protection is enabled */
    char password[64];
    bool password_protection_enabled = get_web_password(password, sizeof(password));

    if (password_protection_enabled && !is_authenticated(req)) {
        ESP_LOGW(TAG, "Unauthenticated access attempt to /firewall");
        /* Redirect to index page with auth_required flag */
        httpd_resp_set_status(req, "303 See Other");
        httpd_resp_set_hdr(req, "Location", "/?auth_required=1");
        httpd_resp_send(req, NULL, 0);
        return ESP_OK;
    }

    char* buf;
    size_t buf_len;
    bool action_performed = false;
    char error_msg[128] = "";

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
            ESP_LOGI(TAG, "Firewall query => %s", buf);

            char param[64];

            /* Check for error parameter first */
            char error_param[128];
            if (httpd_query_key_value(buf, "error", error_param, sizeof(error_param)) == ESP_OK) {
                /* Decode + back to spaces */
                for (char *p = error_param; *p; p++) {
                    if (*p == '+') *p = ' ';
                }
                snprintf(error_msg, sizeof(error_msg), "%s", error_param);
            }

            /* Handle Add Rule */
            if (httpd_query_key_value(buf, "acl_action", param, sizeof(param)) == ESP_OK) {
                if (strcmp(param, "Add+Rule") == 0 || strcmp(param, "Add Rule") == 0) {
                    char list_str[8], proto_str[8], src_ip_str[32], src_port_str[8];
                    char dst_ip_str[32], dst_port_str[8], action_str[8];

                    if (httpd_query_key_value(buf, "acl_list", list_str, sizeof(list_str)) == ESP_OK &&
                        httpd_query_key_value(buf, "proto", proto_str, sizeof(proto_str)) == ESP_OK &&
                        httpd_query_key_value(buf, "src_ip", src_ip_str, sizeof(src_ip_str)) == ESP_OK &&
                        httpd_query_key_value(buf, "dst_ip", dst_ip_str, sizeof(dst_ip_str)) == ESP_OK &&
                        httpd_query_key_value(buf, "action", action_str, sizeof(action_str)) == ESP_OK) {

                        preprocess_string(src_ip_str);
                        preprocess_string(dst_ip_str);

                        uint8_t list_no = atoi(list_str);
                        uint8_t proto = atoi(proto_str);
                        uint8_t action = atoi(action_str);

                        const char *validation_error = NULL;

                        /* Parse source IP (try IP/CIDR first, then device name) */
                        uint32_t src_ip, src_mask;
                        if (strlen(src_ip_str) == 0) {
                            src_ip = 0;
                            src_mask = 0;  /* any */
                        } else if (!acl_parse_ip(src_ip_str, &src_ip, &src_mask)) {
                            /* Try resolving as device name */
                            if (resolve_device_name_to_ip(src_ip_str, &src_ip)) {
                                src_mask = 0xFFFFFFFF;  /* /32 for device names */
                            } else {
                                validation_error = "Invalid source IP address or device name";
                            }
                        }

                        /* Parse destination IP (try IP/CIDR first, then device name) */
                        uint32_t dst_ip, dst_mask;
                        if (validation_error == NULL) {
                            if (strlen(dst_ip_str) == 0) {
                                dst_ip = 0;
                                dst_mask = 0;  /* any */
                            } else if (!acl_parse_ip(dst_ip_str, &dst_ip, &dst_mask)) {
                                /* Try resolving as device name */
                                if (resolve_device_name_to_ip(dst_ip_str, &dst_ip)) {
                                    dst_mask = 0xFFFFFFFF;  /* /32 for device names */
                                } else {
                                    validation_error = "Invalid destination IP address or device name";
                                }
                            }
                        }

                        /* Parse ports */
                        uint16_t s_port = 0, d_port = 0;
                        if (httpd_query_key_value(buf, "src_port", src_port_str, sizeof(src_port_str)) == ESP_OK) {
                            preprocess_string(src_port_str);
                            if (strcmp(src_port_str, "*") != 0 && strlen(src_port_str) > 0) {
                                s_port = atoi(src_port_str);
                            }
                        }
                        if (httpd_query_key_value(buf, "dst_port", dst_port_str, sizeof(dst_port_str)) == ESP_OK) {
                            preprocess_string(dst_port_str);
                            if (strcmp(dst_port_str, "*") != 0 && strlen(dst_port_str) > 0) {
                                d_port = atoi(dst_port_str);
                            }
                        }

                        if (validation_error != NULL) {
                            /* Redirect back with error parameter */
                            char redirect_url[192];
                            snprintf(redirect_url, sizeof(redirect_url), "/firewall?error=%s", validation_error);
                            /* URL encode spaces */
                            for (char *p = redirect_url; *p; p++) {
                                if (*p == ' ') *p = '+';
                            }
                            httpd_resp_set_status(req, "303 See Other");
                            httpd_resp_set_hdr(req, "Location", redirect_url);
                            httpd_resp_send(req, NULL, 0);
                            free(buf);
                            return ESP_OK;
                        }

                        if (list_no < MAX_ACL_LISTS) {
                            if (acl_add(list_no, src_ip, src_mask, dst_ip, dst_mask, proto, s_port, d_port, action)) {
                                save_acl_rules();
                                ESP_LOGI(TAG, "Added ACL rule to list %d", list_no);
                                action_performed = true;
                            }
                        }
                    }
                }
            }

            /* Handle Delete Rule */
            if (httpd_query_key_value(buf, "del_acl", param, sizeof(param)) == ESP_OK) {
                uint8_t list_no = atoi(param);
                char idx_str[8];
                if (httpd_query_key_value(buf, "del_idx", idx_str, sizeof(idx_str)) == ESP_OK) {
                    uint8_t rule_idx = atoi(idx_str);
                    if (list_no < MAX_ACL_LISTS && acl_delete(list_no, rule_idx)) {
                        save_acl_rules();
                        ESP_LOGI(TAG, "Deleted ACL rule %d from list %d", rule_idx, list_no);
                        action_performed = true;
                    }
                }
            }

            /* Handle Clear List */
            if (httpd_query_key_value(buf, "clear_acl", param, sizeof(param)) == ESP_OK) {
                uint8_t list_no = atoi(param);
                if (list_no < MAX_ACL_LISTS) {
                    acl_clear(list_no);
                    save_acl_rules();
                    ESP_LOGI(TAG, "Cleared ACL list %d", list_no);
                    action_performed = true;
                }
            }
        }
        free(buf);
    }

    /* Redirect after action to prevent duplicate submissions on refresh */
    if (action_performed) {
        httpd_resp_set_status(req, "303 See Other");
        httpd_resp_set_hdr(req, "Location", "/firewall");
        httpd_resp_send(req, NULL, 0);
        return ESP_OK;
    }

    /* Reusable buffer for building individual elements */
    char row[384];

    /* --- Begin chunked response --- */

    /* Chunk 1: Page header (styles) */
    httpd_resp_send_chunk(req, FIREWALL_CHUNK_HEAD, HTTPD_RESP_USE_STRLEN);

    /* Chunk 2: Error modal (if any) */
    if (error_msg[0] != '\0') {
        snprintf(row, sizeof(row),
            "<div class='modal-overlay show' id='errorModal'>"
            "<div class='modal-box'>"
            "<h3>Error</h3>"
            "<p>%s</p>"
            "<button onclick=\"document.getElementById('errorModal').classList.remove('show'); history.replaceState(null, '', '/firewall');\">OK</button>"
            "</div>"
            "</div>",
            error_msg);
        httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);
    }

    /* Chunk 3: Container start and header */
    httpd_resp_send_chunk(req, FIREWALL_CHUNK_MID1, HTTPD_RESP_USE_STRLEN);

    /* Chunk 4: Logout button (if authenticated) */
    if (session_active && password_protection_enabled) {
        httpd_resp_send_chunk(req,
            "<a href='/?logout=1' style='padding: 0.4rem 1rem; background: rgba(255,82,82,0.15); color: #ff5252; border: 1px solid #ff5252; border-radius: 6px; text-decoration: none; font-size: 0.85rem; font-weight: 500;'>Logout</a>",
            HTTPD_RESP_USE_STRLEN);
    }

    /* Chunk 5: Description text */
    httpd_resp_send_chunk(req, FIREWALL_CHUNK_MID2, HTTPD_RESP_USE_STRLEN);

    /* Chunk 6: Stream ACL sections */
    for (int list_no = 0; list_no < MAX_ACL_LISTS; list_no++) {
        acl_entry_t* rules = acl_get_rules(list_no);
        acl_stats_t* stats = acl_get_stats(list_no);
        const char* list_desc = acl_get_desc(list_no);

        /* Section header with stats */
        snprintf(row, sizeof(row),
            "<div class='acl-section'>"
            "<h3>%s</h3>"
            "<div class='stats'>"
            "<span class='allowed'>Allowed: %lu</span>"
            "<span class='denied'>Denied: %lu</span>"
            "<span>No match: %lu</span>"
            "<a href='/firewall?clear_acl=%d' class='orange-button' style='float:right;'>Clear</a>"
            "</div>",
            list_desc,
            (unsigned long)stats->packets_allowed,
            (unsigned long)stats->packets_denied,
            (unsigned long)stats->packets_nomatch,
            list_no);
        httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);

        /* Rules table header */
        httpd_resp_send_chunk(req,
            "<table class='data-table'>"
            "<thead><tr>"
            "<th>#</th><th>Proto</th><th>Source</th><th>SPort</th>"
            "<th>Dest</th><th>DPort</th><th>Action</th><th>Hits</th><th></th>"
            "</tr></thead><tbody>",
            HTTPD_RESP_USE_STRLEN);

        /* Stream rule rows */
        int rule_count = 0;
        for (int i = 0; i < MAX_ACL_ENTRIES; i++) {
            if (!rules[i].valid) continue;
            rule_count++;

            /* Format protocol */
            const char *proto_str;
            switch (rules[i].proto) {
                case 0:  proto_str = "IP"; break;
                case 1:  proto_str = "ICMP"; break;
                case 6:  proto_str = "TCP"; break;
                case 17: proto_str = "UDP"; break;
                default: proto_str = "?"; break;
            }

            /* Format IP addresses with device names for /32 */
            char src_str[DHCP_RESERVATION_NAME_LEN], dst_str[DHCP_RESERVATION_NAME_LEN];
            if (rules[i].s_mask == 0xFFFFFFFF) {
                const char* name = lookup_device_name_by_ip(rules[i].src);
                if (name) {
                    snprintf(src_str, sizeof(src_str), "%s", name);
                } else {
                    acl_format_ip(rules[i].src, rules[i].s_mask, src_str, sizeof(src_str));
                }
            } else {
                acl_format_ip(rules[i].src, rules[i].s_mask, src_str, sizeof(src_str));
            }
            if (rules[i].d_mask == 0xFFFFFFFF) {
                const char* name = lookup_device_name_by_ip(rules[i].dest);
                if (name) {
                    snprintf(dst_str, sizeof(dst_str), "%s", name);
                } else {
                    acl_format_ip(rules[i].dest, rules[i].d_mask, dst_str, sizeof(dst_str));
                }
            } else {
                acl_format_ip(rules[i].dest, rules[i].d_mask, dst_str, sizeof(dst_str));
            }

            /* Format ports */
            char s_port_str[8], d_port_str[8];
            if (rules[i].s_port == 0) strcpy(s_port_str, "*");
            else snprintf(s_port_str, sizeof(s_port_str), "%d", rules[i].s_port);
            if (rules[i].d_port == 0) strcpy(d_port_str, "*");
            else snprintf(d_port_str, sizeof(d_port_str), "%d", rules[i].d_port);

            /* Format action */
            const char *action_str;
            uint8_t action = rules[i].allow & 0x01;
            uint8_t monitor = rules[i].allow & ACL_MONITOR;
            if (action == ACL_ALLOW) {
                action_str = monitor ? "Allow+M" : "Allow";
            } else {
                action_str = monitor ? "Deny+M" : "Deny";
            }

            snprintf(row, sizeof(row),
                "<tr>"
                "<td>%d</td><td>%s</td><td>%s</td><td>%s</td>"
                "<td>%s</td><td>%s</td><td>%s</td><td>%lu</td>"
                "<td><a href='/firewall?del_acl=%d&del_idx=%d' class='red-button'>Del</a></td>"
                "</tr>",
                i, proto_str, src_str, s_port_str,
                dst_str, d_port_str, action_str, (unsigned long)rules[i].hit_count,
                list_no, i);
            httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);
        }

        if (rule_count == 0) {
            httpd_resp_send_chunk(req,
                "<tr><td colspan='9' style='text-align:center; color:#888;'>No rules (all packets allowed)</td></tr>",
                HTTPD_RESP_USE_STRLEN);
        }

        /* Close table and section */
        httpd_resp_send_chunk(req, "</tbody></table></div>", HTTPD_RESP_USE_STRLEN);
    }

    /* Chunk 7: Add form and footer */
    httpd_resp_send_chunk(req, FIREWALL_CHUNK_TAIL, HTTPD_RESP_USE_STRLEN);

    /* End chunked response */
    httpd_resp_send_chunk(req, NULL, 0);

    return ESP_OK;
}

static httpd_uri_t firewallp = {
    .uri       = "/firewall",
    .method    = HTTP_GET,
    .handler   = firewall_get_handler,
};

/* Helper function to convert auth mode to string for web UI */
static const char* web_auth_mode_to_str(wifi_auth_mode_t authmode)
{
    switch (authmode) {
        case WIFI_AUTH_OPEN:            return "Open";
        case WIFI_AUTH_WEP:             return "WEP";
        case WIFI_AUTH_WPA_PSK:         return "WPA";
        case WIFI_AUTH_WPA2_PSK:        return "WPA2";
        case WIFI_AUTH_WPA_WPA2_PSK:    return "WPA/WPA2";
        case WIFI_AUTH_WPA3_PSK:        return "WPA3";
        case WIFI_AUTH_WPA2_WPA3_PSK:   return "WPA2/WPA3";
        case WIFI_AUTH_WPA2_ENTERPRISE: return "WPA2-Ent";
        default:                        return "Unknown";
    }
}

/* URL encode a string for use in query parameters */
static void url_encode(const char *src, char *dst, size_t dst_len)
{
    const char *hex = "0123456789ABCDEF";
    size_t i = 0;

    while (*src && i < dst_len - 1) {
        if ((*src >= 'A' && *src <= 'Z') ||
            (*src >= 'a' && *src <= 'z') ||
            (*src >= '0' && *src <= '9') ||
            *src == '-' || *src == '_' || *src == '.' || *src == '~') {
            dst[i++] = *src;
        } else if (i + 3 < dst_len) {
            dst[i++] = '%';
            dst[i++] = hex[(*src >> 4) & 0x0F];
            dst[i++] = hex[*src & 0x0F];
        } else {
            break;
        }
        src++;
    }
    dst[i] = '\0';
}

/* WiFi Scan page GET handler - NOT password protected */
static esp_err_t scan_get_handler(httpd_req_t *req)
{
    /* Check if user can connect (authenticated or no password set) */
    char password[64];
    bool password_protection_enabled = get_web_password(password, sizeof(password));
    bool can_connect = !password_protection_enabled || is_authenticated(req);

    uint16_t ap_count = 0;
    wifi_ap_record_t *ap_list = NULL;
    bool scan_in_progress = false;
    int refresh_time = 15;  /* Default refresh interval */

    /* Try to get existing scan results first */
    esp_err_t err = esp_wifi_scan_get_ap_num(&ap_count);

    if (err == ESP_OK && ap_count > 0) {
        /* We have results from a previous scan */
        if (ap_count > 20) ap_count = 20;
        ap_list = malloc(sizeof(wifi_ap_record_t) * ap_count);
        if (ap_list != NULL) {
            esp_wifi_scan_get_ap_records(&ap_count, ap_list);
        } else {
            ap_count = 0;
        }

        /* Start a new scan in the background for the next refresh */
        wifi_scan_config_t scan_config = {
            .ssid = NULL,
            .bssid = NULL,
            .channel = 0,
            .show_hidden = true,
            .scan_type = WIFI_SCAN_TYPE_ACTIVE,
        };
        esp_wifi_scan_start(&scan_config, false);  /* Non-blocking */
    } else {
        /* No results available, start a scan */
        wifi_scan_config_t scan_config = {
            .ssid = NULL,
            .bssid = NULL,
            .channel = 0,
            .show_hidden = true,
            .scan_type = WIFI_SCAN_TYPE_ACTIVE,
        };
        err = esp_wifi_scan_start(&scan_config, false);  /* Non-blocking */

        if (err == ESP_OK || err == ESP_ERR_WIFI_STATE) {
            /* Scan started or already in progress */
            scan_in_progress = true;
            refresh_time = 2;  /* Quick refresh to get results */
        }
    }

    /* Build the table header with optional Connect column */
    char header_extra[64] = "";
    if (can_connect) {
        strcpy(header_extra, "<th>Action</th>");
    }

    /* Build scan results HTML */
    char scan_html[4096] = "";
    int html_offset = 0;

    if (ap_count == 0) {
        if (scan_in_progress) {
            snprintf(scan_html, sizeof(scan_html),
                "<tr><td colspan='%d' style='text-align:center; color:#00d9ff;'>"
                "<span style='display:inline-block; animation: pulse 1s infinite;'>📡 Scanning...</span>"
                "</td></tr>",
                can_connect ? 4 : 3);
        } else {
            snprintf(scan_html, sizeof(scan_html),
                "<tr><td colspan='%d' style='text-align:center; color:#888;'>No networks found</td></tr>",
                can_connect ? 4 : 3);
        }
    } else {
        for (int i = 0; i < ap_count && html_offset < (int)(sizeof(scan_html) - 512); i++) {
            /* Determine signal strength and build visual bars */
            const char *signal_class;
            int rssi = ap_list[i].rssi;
            int bars;  /* Number of active bars (1-4) */

            if (rssi >= -50) {
                signal_class = "signal-excellent";
                bars = 4;
            } else if (rssi >= -60) {
                signal_class = "signal-good";
                bars = 3;
            } else if (rssi >= -70) {
                signal_class = "signal-fair";
                bars = 2;
            } else if (rssi >= -80) {
                signal_class = "signal-weak";
                bars = 1;
            } else {
                signal_class = "signal-poor";
                bars = 1;
            }

            /* HTML-escape SSID for display */
            char *safe_ssid = html_escape((const char *)ap_list[i].ssid);
            if (safe_ssid == NULL) {
                safe_ssid = strdup("(unknown)");
            }

            /* Build connect button if allowed */
            char connect_cell[256] = "";
            if (can_connect) {
                char encoded_ssid[128];
                url_encode((const char *)ap_list[i].ssid, encoded_ssid, sizeof(encoded_ssid));
                snprintf(connect_cell, sizeof(connect_cell),
                    "<td><a href='/config?ssid=%s' class='connect-button'>Connect</a></td>",
                    encoded_ssid);
            }

            /* Build signal bars HTML with active/inactive styling */
            char signal_bars_html[128];
            const char *bar_chars[] = {"▂", "▄", "▆", "█"};
            int sb_offset = 0;
            for (int b = 0; b < 4; b++) {
                if (b < bars) {
                    sb_offset += snprintf(signal_bars_html + sb_offset, sizeof(signal_bars_html) - sb_offset,
                        "<span class='%s'>%s</span>", signal_class, bar_chars[b]);
                } else {
                    sb_offset += snprintf(signal_bars_html + sb_offset, sizeof(signal_bars_html) - sb_offset,
                        "<span style='color:#444;'>%s</span>", bar_chars[b]);
                }
            }

            html_offset += snprintf(scan_html + html_offset, sizeof(scan_html) - html_offset,
                "<tr>"
                "<td>%s</td>"
                "<td>%s <span style='color:#888;font-size:0.8rem;'>%d dBm</span></td>"
                "<td>%s</td>"
                "%s"
                "</tr>",
                safe_ssid,
                signal_bars_html, rssi,
                web_auth_mode_to_str(ap_list[i].authmode),
                connect_cell
            );

            free(safe_ssid);
        }
    }

    if (ap_list != NULL) {
        free(ap_list);
    }

    /* Build the page */
    const char* scan_page_template = SCAN_PAGE;
    int page_len = strlen(scan_page_template) + strlen(header_extra) + strlen(scan_html) + 128;
    char* scan_page = malloc(page_len);

    if (scan_page == NULL) {
        ESP_LOGE(TAG, "Failed to allocate memory for scan page");
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Out of memory");
        return ESP_ERR_NO_MEM;
    }

    snprintf(scan_page, page_len, scan_page_template, refresh_time, ap_count, header_extra, scan_html);

    httpd_resp_send(req, scan_page, strlen(scan_page));
    free(scan_page);

    return ESP_OK;
}

static httpd_uri_t scanp = {
    .uri       = "/scan",
    .method    = HTTP_GET,
    .handler   = scan_get_handler,
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
        httpd_register_uri_handler(server, &firewallp);
        httpd_register_uri_handler(server, &scanp);
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
