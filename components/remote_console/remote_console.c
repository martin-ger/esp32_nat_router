/**
 * @file remote_console.c
 * @brief Secure remote console implementation
 *
 * Phase 1: Plain TCP with password authentication
 * Phase 2 will add TLS encryption
 */

#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_console.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "lwip/sockets.h"

#include "remote_console.h"

/* NVS namespace - must match router_globals.h */
#define PARAM_NAMESPACE "esp32_nat"

/* MSG_NOSIGNAL may not be defined on all platforms */
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

static const char *TAG = "remote_console";

/* NVS keys */
#define NVS_KEY_ENABLED     "rc_enabled"
#define NVS_KEY_PORT        "rc_port"
#define NVS_KEY_BIND        "rc_bind"
#define NVS_KEY_TIMEOUT     "rc_timeout"

/* Task configuration */
#define RC_TASK_STACK_SIZE  6144
#define RC_TASK_PRIORITY    5

/* Protocol constants */
#define RC_MAX_LINE_LEN     256
#define RC_OUTPUT_BUF_SIZE  4096
#define RC_MAX_AUTH_ATTEMPTS 3
#define RC_AUTH_DELAY_MS    5000

/* Banner and prompts */
static const char *RC_BANNER =
    "\r\n"
    "============================================\r\n"
    "  ESP32 NAT Router - Remote Console\r\n"
    "  WARNING: Plain TCP (not encrypted)\r\n"
    "============================================\r\n"
    "\r\n";

static const char *RC_PROMPT = "esp32> ";
static const char *RC_AUTH_PROMPT = "Password: ";
static const char *RC_AUTH_OK = "\r\nAuthentication successful.\r\n\r\n";
static const char *RC_AUTH_FAIL = "\r\nAuthentication failed.\r\n";
static const char *RC_BUSY = "BUSY: Another session is active.\r\n";
static const char *RC_NO_PASSWORD = "ERROR: No password set. Set via web interface or 'set_web_password' command.\r\n";
static const char *RC_GOODBYE = "\r\nGoodbye.\r\n";

/* State */
static remote_console_config_t rc_config = {
    .enabled = false,
    .port = REMOTE_CONSOLE_DEFAULT_PORT,
    .bind = RC_BIND_AP_ONLY,
    .idle_timeout_sec = REMOTE_CONSOLE_DEFAULT_TIMEOUT
};

static struct {
    remote_console_state_t state;
    int server_socket;
    int client_socket;
    char client_ip[16];
    int64_t session_start_time;
    int64_t last_activity_time;
    uint32_t total_connections;
    uint32_t failed_auths;
    TaskHandle_t task_handle;
    SemaphoreHandle_t session_mutex;
    volatile bool kick_requested;
    volatile bool shutdown_requested;
} rc_state = {
    .state = RC_STATE_DISABLED,
    .server_socket = -1,
    .client_socket = -1,
    .task_handle = NULL,
    .session_mutex = NULL,
    .kick_requested = false,
    .shutdown_requested = false
};

/* Output redirection state */
static int rc_client_fd = -1;           /* Socket for active session output */

/* Capture buffer for stdout - larger for help output */
#define RC_CAPTURE_BUF_SIZE 8192
static char rc_capture_buf[RC_CAPTURE_BUF_SIZE];
static size_t rc_capture_pos = 0;
static bool rc_capturing = false;


/* Forward declarations */
static void remote_console_task(void *arg);
static esp_err_t load_config(void);
static esp_err_t save_config(void);
static bool get_web_password(char *password, size_t max_len);
static bool authenticate_client(int client_fd);
static void handle_session(int client_fd);
static int send_string(int fd, const char *str);
static int recv_line(int fd, char *buf, size_t max_len, uint32_t timeout_sec);

/* External declarations for wrapped functions */
extern int __real_printf(const char *fmt, ...);
extern int __real_puts(const char *s);
extern int __real_putchar(int c);
extern int __real_fputs(const char *s, FILE *stream);
extern size_t __real_fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);

/**
 * @brief Helper to add data to capture buffer
 */
static void rc_capture_add(const char *data, size_t len) {
    if (!rc_capturing || len == 0) return;
    if (rc_capture_pos >= RC_CAPTURE_BUF_SIZE - 1) return;

    size_t copy_len = len;
    if (rc_capture_pos + copy_len >= RC_CAPTURE_BUF_SIZE) {
        copy_len = RC_CAPTURE_BUF_SIZE - 1 - rc_capture_pos;
    }
    memcpy(rc_capture_buf + rc_capture_pos, data, copy_len);
    rc_capture_pos += copy_len;
    rc_capture_buf[rc_capture_pos] = '\0';
}

/**
 * @brief Wrapped printf - intercepts all printf calls
 */
int __wrap_printf(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);

    /* Use a small stack buffer */
    char buf[256];
    int len = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    if (len > 0) {
        /* Always output to serial console */
        __real_printf("%s", buf);
        /* Capture for remote console if active */
        if (rc_capturing) {
            rc_capture_add(buf, len < (int)sizeof(buf) ? len : sizeof(buf) - 1);
        }
    }

    return len;
}

/**
 * @brief Wrapped puts - intercepts all puts calls
 */
int __wrap_puts(const char *s) {
    /* Always output to serial console */
    int ret = __real_puts(s);

    /* Capture for remote console (including newline) */
    if (rc_capturing) {
        size_t len = strlen(s);
        rc_capture_add(s, len);
        rc_capture_add("\n", 1);
    }

    return ret;
}

/**
 * @brief Wrapped putchar - intercepts all putchar calls
 */
int __wrap_putchar(int c) {
    /* Always output to serial console */
    int ret = __real_putchar(c);

    /* Capture for remote console */
    if (rc_capturing) {
        char ch = (char)c;
        rc_capture_add(&ch, 1);
    }

    return ret;
}

/**
 * @brief Wrapped fputs - intercepts fputs calls to stdout/stderr
 */
int __wrap_fputs(const char *s, FILE *stream) {
    /* Always output to original stream */
    int ret = __real_fputs(s, stream);

    /* Capture stdout and stderr for remote console */
    if (rc_capturing && (stream == stdout || stream == stderr)) {
        rc_capture_add(s, strlen(s));
    }

    return ret;
}

/**
 * @brief Wrapped fwrite - intercepts fwrite calls to stdout/stderr
 */
size_t __wrap_fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
    /* Always output to original stream */
    size_t ret = __real_fwrite(ptr, size, nmemb, stream);

    /* Capture stdout and stderr for remote console */
    if (rc_capturing && (stream == stdout || stream == stderr)) {
        rc_capture_add((const char *)ptr, size * nmemb);
    }

    return ret;
}

/**
 * @brief Send data to network client with LF->CRLF conversion
 */
static void send_to_client_crlf(int fd, const char *data, size_t len) {
    if (fd < 0 || len == 0) return;

    char net_buf[512];
    size_t net_pos = 0;

    for (size_t i = 0; i < len; i++) {
        if (data[i] == '\n' && (i == 0 || data[i-1] != '\r')) {
            if (net_pos < sizeof(net_buf) - 1) {
                net_buf[net_pos++] = '\r';
            }
        }
        if (net_pos < sizeof(net_buf)) {
            net_buf[net_pos++] = data[i];
        }

        /* Flush buffer if full */
        if (net_pos >= sizeof(net_buf) - 2) {
            send(fd, net_buf, net_pos, MSG_NOSIGNAL);
            net_pos = 0;
        }
    }

    /* Send remaining */
    if (net_pos > 0) {
        send(fd, net_buf, net_pos, MSG_NOSIGNAL);
    }
}


esp_err_t remote_console_init(void) {
    ESP_LOGI(TAG, "Initializing remote console");

    /* Create session mutex */
    rc_state.session_mutex = xSemaphoreCreateMutex();
    if (rc_state.session_mutex == NULL) {
        ESP_LOGE(TAG, "Failed to create session mutex");
        return ESP_ERR_NO_MEM;
    }

    /* Load configuration from NVS */
    load_config();

    /* Start server if enabled */
    if (rc_config.enabled) {
        /* Check if password is set */
        char password[64];
        if (!get_web_password(password, sizeof(password))) {
            ESP_LOGW(TAG, "Remote console enabled but no password set - not starting");
            rc_state.state = RC_STATE_DISABLED;
            return ESP_OK;
        }

        /* Create server task */
        BaseType_t ret = xTaskCreate(remote_console_task, "remote_console",
                                     RC_TASK_STACK_SIZE, NULL,
                                     RC_TASK_PRIORITY, &rc_state.task_handle);
        if (ret != pdPASS) {
            ESP_LOGE(TAG, "Failed to create remote console task");
            return ESP_ERR_NO_MEM;
        }

        rc_state.state = RC_STATE_LISTENING;
        ESP_LOGI(TAG, "Remote console started on port %d", rc_config.port);
    } else {
        rc_state.state = RC_STATE_DISABLED;
        ESP_LOGI(TAG, "Remote console disabled");
    }

    return ESP_OK;
}

esp_err_t remote_console_enable(void) {
    if (rc_config.enabled) {
        return ESP_OK;  /* Already enabled */
    }

    /* Check if password is set */
    char password[64];
    if (!get_web_password(password, sizeof(password))) {
        ESP_LOGE(TAG, "Cannot enable remote console: no password set");
        return ESP_ERR_INVALID_STATE;
    }

    rc_config.enabled = true;
    save_config();

    /* Start server if not already running */
    if (rc_state.task_handle == NULL) {
        rc_state.shutdown_requested = false;
        BaseType_t ret = xTaskCreate(remote_console_task, "remote_console",
                                     RC_TASK_STACK_SIZE, NULL,
                                     RC_TASK_PRIORITY, &rc_state.task_handle);
        if (ret != pdPASS) {
            ESP_LOGE(TAG, "Failed to create remote console task");
            rc_config.enabled = false;
            save_config();
            return ESP_ERR_NO_MEM;
        }
        rc_state.state = RC_STATE_LISTENING;
    }

    ESP_LOGI(TAG, "Remote console enabled on port %d", rc_config.port);
    return ESP_OK;
}

esp_err_t remote_console_disable(void) {
    if (!rc_config.enabled) {
        return ESP_OK;  /* Already disabled */
    }

    rc_config.enabled = false;
    save_config();

    /* Signal shutdown and kick any active session */
    rc_state.shutdown_requested = true;
    rc_state.kick_requested = true;

    /* Close server socket to unblock accept() */
    if (rc_state.server_socket >= 0) {
        close(rc_state.server_socket);
        rc_state.server_socket = -1;
    }

    /* Wait for task to exit */
    if (rc_state.task_handle != NULL) {
        /* Give task time to clean up */
        vTaskDelay(pdMS_TO_TICKS(500));
        rc_state.task_handle = NULL;
    }

    rc_state.state = RC_STATE_DISABLED;
    ESP_LOGI(TAG, "Remote console disabled");
    return ESP_OK;
}

esp_err_t remote_console_set_port(uint16_t port) {
    if (port == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    rc_config.port = port;
    save_config();

    ESP_LOGI(TAG, "Port set to %d (restart required)", port);
    return ESP_OK;
}

esp_err_t remote_console_set_bind(remote_console_bind_t bind) {
    if (bind > RC_BIND_STA_ONLY) {
        return ESP_ERR_INVALID_ARG;
    }

    rc_config.bind = bind;
    save_config();

    const char *bind_str[] = {"both", "AP only", "STA only"};
    ESP_LOGI(TAG, "Bind set to %s (restart required)", bind_str[bind]);
    return ESP_OK;
}

esp_err_t remote_console_set_timeout(uint32_t timeout_sec) {
    rc_config.idle_timeout_sec = timeout_sec;
    save_config();

    ESP_LOGI(TAG, "Idle timeout set to %lu seconds", (unsigned long)timeout_sec);
    return ESP_OK;
}

esp_err_t remote_console_kick(void) {
    if (rc_state.state != RC_STATE_ACTIVE) {
        return ESP_ERR_NOT_FOUND;
    }

    rc_state.kick_requested = true;
    ESP_LOGI(TAG, "Kick requested for client %s", rc_state.client_ip);
    return ESP_OK;
}

esp_err_t remote_console_get_config(remote_console_config_t *config) {
    if (config == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    *config = rc_config;
    return ESP_OK;
}

esp_err_t remote_console_get_status(remote_console_status_t *status) {
    if (status == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    memset(status, 0, sizeof(*status));
    status->state = rc_state.state;
    status->total_connections = rc_state.total_connections;
    status->failed_auths = rc_state.failed_auths;

    if (rc_state.state == RC_STATE_ACTIVE) {
        strncpy(status->client_ip, rc_state.client_ip, sizeof(status->client_ip) - 1);
        int64_t now = esp_timer_get_time();
        status->session_duration_sec = (uint32_t)((now - rc_state.session_start_time) / 1000000);
        status->idle_sec = (uint32_t)((now - rc_state.last_activity_time) / 1000000);
    }

    return ESP_OK;
}

bool remote_console_is_enabled(void) {
    return rc_config.enabled;
}

bool remote_console_session_active(void) {
    return rc_state.state == RC_STATE_ACTIVE;
}

/* ---- Private functions ---- */

static esp_err_t load_config(void) {
    nvs_handle_t nvs;
    esp_err_t err = nvs_open(PARAM_NAMESPACE, NVS_READONLY, &nvs);
    if (err != ESP_OK) {
        return err;
    }

    uint8_t u8_val;
    uint16_t u16_val;
    uint32_t u32_val;

    if (nvs_get_u8(nvs, NVS_KEY_ENABLED, &u8_val) == ESP_OK) {
        rc_config.enabled = (u8_val != 0);
    }
    if (nvs_get_u16(nvs, NVS_KEY_PORT, &u16_val) == ESP_OK) {
        rc_config.port = u16_val;
    }
    if (nvs_get_u8(nvs, NVS_KEY_BIND, &u8_val) == ESP_OK) {
        rc_config.bind = (remote_console_bind_t)u8_val;
    }
    if (nvs_get_u32(nvs, NVS_KEY_TIMEOUT, &u32_val) == ESP_OK) {
        rc_config.idle_timeout_sec = u32_val;
    }

    nvs_close(nvs);
    return ESP_OK;
}

static esp_err_t save_config(void) {
    nvs_handle_t nvs;
    esp_err_t err = nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) {
        return err;
    }

    nvs_set_u8(nvs, NVS_KEY_ENABLED, rc_config.enabled ? 1 : 0);
    nvs_set_u16(nvs, NVS_KEY_PORT, rc_config.port);
    nvs_set_u8(nvs, NVS_KEY_BIND, (uint8_t)rc_config.bind);
    nvs_set_u32(nvs, NVS_KEY_TIMEOUT, rc_config.idle_timeout_sec);

    nvs_commit(nvs);
    nvs_close(nvs);
    return ESP_OK;
}

static bool get_web_password(char *password, size_t max_len) {
    nvs_handle_t nvs;
    esp_err_t err = nvs_open(PARAM_NAMESPACE, NVS_READONLY, &nvs);
    if (err != ESP_OK) {
        return false;
    }

    size_t required_size = max_len;
    err = nvs_get_str(nvs, "web_password", password, &required_size);
    nvs_close(nvs);

    if (err != ESP_OK || required_size == 0 || password[0] == '\0') {
        return false;
    }

    return true;
}

static int send_string(int fd, const char *str) {
    size_t len = strlen(str);
    ssize_t sent = send(fd, str, len, 0);
    return (sent == (ssize_t)len) ? 0 : -1;
}

static int recv_line(int fd, char *buf, size_t max_len, uint32_t timeout_sec) {
    size_t pos = 0;
    int64_t start = esp_timer_get_time();
    int64_t timeout_us = (int64_t)timeout_sec * 1000000;

    /* Set socket timeout */
    struct timeval tv;
    tv.tv_sec = 1;  /* 1 second poll interval */
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    while (pos < max_len - 1) {
        /* Check for kick or shutdown */
        if (rc_state.kick_requested || rc_state.shutdown_requested) {
            return -1;
        }

        /* Check timeout */
        if (timeout_sec > 0) {
            int64_t elapsed = esp_timer_get_time() - start;
            if (elapsed > timeout_us) {
                return -2;  /* Timeout */
            }
        }

        char c;
        ssize_t ret = recv(fd, &c, 1, 0);

        if (ret < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;  /* Timeout on recv, check for kick/shutdown */
            }
            return -1;  /* Error */
        } else if (ret == 0) {
            return -1;  /* Connection closed */
        }

        /* Handle special characters */
        if (c == '\r') {
            continue;  /* Ignore CR */
        } else if (c == '\n') {
            buf[pos] = '\0';
            return (int)pos;
        } else if (c == '\b' || c == 0x7f) {
            /* Backspace */
            if (pos > 0) {
                pos--;
                send(fd, "\b \b", 3, 0);  /* Erase character */
            }
        } else if (c == 0x03) {
            /* Ctrl+C */
            return -3;
        } else if (c == 0x04) {
            /* Ctrl+D */
            return -1;
        } else if (c >= 0x20 && c < 0x7f) {
            buf[pos++] = c;
        }
    }

    buf[pos] = '\0';
    return (int)pos;
}

static bool authenticate_client(int client_fd) {
    char password_stored[64];
    char password_input[64];

    /* Get stored password */
    if (!get_web_password(password_stored, sizeof(password_stored))) {
        send_string(client_fd, RC_NO_PASSWORD);
        return false;
    }

    for (int attempt = 0; attempt < RC_MAX_AUTH_ATTEMPTS; attempt++) {
        send_string(client_fd, RC_AUTH_PROMPT);

        /* Receive password (with echo disabled - we don't echo) */
        int len = recv_line(client_fd, password_input, sizeof(password_input), 60);
        if (len < 0) {
            return false;
        }

        /* Constant-time comparison to prevent timing attacks */
        size_t stored_len = strlen(password_stored);
        size_t input_len = strlen(password_input);
        size_t max_len = (stored_len > input_len) ? stored_len : input_len;

        volatile int diff = (stored_len != input_len);
        for (size_t i = 0; i < max_len; i++) {
            char a = (i < stored_len) ? password_stored[i] : 0;
            char b = (i < input_len) ? password_input[i] : 0;
            diff |= (a ^ b);
        }

        if (diff == 0) {
            send_string(client_fd, RC_AUTH_OK);
            return true;
        }

        send_string(client_fd, RC_AUTH_FAIL);
        rc_state.failed_auths++;

        if (attempt < RC_MAX_AUTH_ATTEMPTS - 1) {
            send_string(client_fd, "\r\n");
        }
    }

    /* Max attempts reached */
    ESP_LOGW(TAG, "Authentication failed from %s after %d attempts",
             rc_state.client_ip, RC_MAX_AUTH_ATTEMPTS);

    /* Delay before allowing reconnection */
    vTaskDelay(pdMS_TO_TICKS(RC_AUTH_DELAY_MS));

    return false;
}

static void handle_session(int client_fd) {
    char line[RC_MAX_LINE_LEN];
    int ret;

    rc_state.state = RC_STATE_ACTIVE;
    rc_state.session_start_time = esp_timer_get_time();
    rc_state.last_activity_time = rc_state.session_start_time;

    ESP_LOGI(TAG, "Session started with %s", rc_state.client_ip);

    /* Set client fd for any direct sends */
    rc_client_fd = client_fd;

    /* Send initial prompt */
    send_string(client_fd, RC_PROMPT);

    while (!rc_state.kick_requested && !rc_state.shutdown_requested) {
        /* Receive command line */
        ret = recv_line(client_fd, line, sizeof(line), rc_config.idle_timeout_sec);

        if (ret == -2) {
            /* Timeout */
            send_string(client_fd, "\r\nSession timeout.\r\n");
            break;
        } else if (ret == -3) {
            /* Ctrl+C - cancel current line, show new prompt */
            send_string(client_fd, "^C\r\n");
            send_string(client_fd, RC_PROMPT);
            continue;
        } else if (ret < 0) {
            /* Error or disconnect (including Ctrl+D) */
            break;
        }

        rc_state.last_activity_time = esp_timer_get_time();

        /* Empty line - just show prompt */
        if (ret == 0) {
            send_string(client_fd, RC_PROMPT);
            continue;
        }

        /* Check for quit command */
        if (strcmp(line, "quit") == 0 || strcmp(line, "exit") == 0) {
            send_string(client_fd, RC_GOODBYE);
            break;
        }

        /* Start capturing output */
        rc_capture_pos = 0;
        rc_capture_buf[0] = '\0';
        rc_capturing = true;

        /* Execute command */
        int cmd_ret;
        esp_err_t err = esp_console_run(line, &cmd_ret);

        /* Flush stdout to ensure all output is captured */
        fflush(stdout);

        /* Stop capturing - MUST happen even if command fails */
        rc_capturing = false;

        /* Send captured output to client */
        if (rc_capture_pos > 0) {
            send_to_client_crlf(client_fd, rc_capture_buf, rc_capture_pos);
        }

        /* Handle command result */
        if (err == ESP_ERR_NOT_FOUND) {
            send_string(client_fd, "Unknown command. Type 'help' for list.\r\n");
        } else if (err == ESP_ERR_INVALID_ARG) {
            /* Command parsing error - output already sent */
        } else if (err != ESP_OK) {
            char errbuf[64];
            snprintf(errbuf, sizeof(errbuf), "Error: %s\r\n", esp_err_to_name(err));
            send_string(client_fd, errbuf);
        }

        /* Send prompt */
        send_string(client_fd, RC_PROMPT);
    }

    /* Clear state */
    rc_client_fd = -1;
    rc_capturing = false;  /* Ensure capturing is disabled */

    ESP_LOGI(TAG, "Session ended with %s", rc_state.client_ip);
}

static void remote_console_task(void *arg) {
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len;
    int opt = 1;

    ESP_LOGI(TAG, "Remote console task started");

    while (!rc_state.shutdown_requested) {
        /* Create server socket */
        rc_state.server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (rc_state.server_socket < 0) {
            ESP_LOGE(TAG, "Failed to create socket: %d", errno);
            vTaskDelay(pdMS_TO_TICKS(5000));
            continue;
        }

        /* Set socket options */
        setsockopt(rc_state.server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        /* Bind to port */
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(rc_config.port);
        server_addr.sin_addr.s_addr = htonl(INADDR_ANY);  /* TODO: implement bind filtering */

        if (bind(rc_state.server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            ESP_LOGE(TAG, "Failed to bind to port %d: %d", rc_config.port, errno);
            close(rc_state.server_socket);
            rc_state.server_socket = -1;
            vTaskDelay(pdMS_TO_TICKS(5000));
            continue;
        }

        /* Listen */
        if (listen(rc_state.server_socket, 1) < 0) {
            ESP_LOGE(TAG, "Failed to listen: %d", errno);
            close(rc_state.server_socket);
            rc_state.server_socket = -1;
            vTaskDelay(pdMS_TO_TICKS(5000));
            continue;
        }

        rc_state.state = RC_STATE_LISTENING;
        ESP_LOGI(TAG, "Listening on port %d", rc_config.port);

        /* Accept loop */
        while (!rc_state.shutdown_requested) {
            client_len = sizeof(client_addr);
            rc_state.client_socket = accept(rc_state.server_socket,
                                           (struct sockaddr *)&client_addr,
                                           &client_len);

            if (rc_state.client_socket < 0) {
                if (rc_state.shutdown_requested) {
                    break;
                }
                if (errno != EINTR) {
                    ESP_LOGE(TAG, "Accept failed: %d", errno);
                }
                continue;
            }

            /* Get client IP */
            inet_ntop(AF_INET, &client_addr.sin_addr, rc_state.client_ip, sizeof(rc_state.client_ip));
            rc_state.total_connections++;

            ESP_LOGI(TAG, "Connection from %s", rc_state.client_ip);

            /* Try to acquire session mutex */
            if (xSemaphoreTake(rc_state.session_mutex, 0) != pdTRUE) {
                send_string(rc_state.client_socket, RC_BUSY);
                close(rc_state.client_socket);
                rc_state.client_socket = -1;
                continue;
            }

            /* Send banner */
            send_string(rc_state.client_socket, RC_BANNER);

            /* Authenticate */
            rc_state.state = RC_STATE_AUTH_WAIT;
            rc_state.kick_requested = false;

            if (authenticate_client(rc_state.client_socket)) {
                /* Handle session */
                handle_session(rc_state.client_socket);
            }

            /* Cleanup */
            close(rc_state.client_socket);
            rc_state.client_socket = -1;
            rc_state.client_ip[0] = '\0';
            rc_state.state = RC_STATE_LISTENING;
            rc_state.kick_requested = false;

            xSemaphoreGive(rc_state.session_mutex);
        }

        /* Close server socket */
        if (rc_state.server_socket >= 0) {
            close(rc_state.server_socket);
            rc_state.server_socket = -1;
        }
    }

    rc_state.state = RC_STATE_DISABLED;
    rc_state.task_handle = NULL;
    ESP_LOGI(TAG, "Remote console task exiting");
    vTaskDelete(NULL);
}
