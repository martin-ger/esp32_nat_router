/**
 * @file remote_console.c
 * @brief Remote console over SSH
 *
 * The network CLI is reachable only through SSH (see ssh_transport.c): the
 * connection is encrypted and the router password is checked inside the
 * encrypted channel.  One session at a time; buffers exist only while a
 * client is connected.
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
#include "lwip/ip4_addr.h"
#include "mbedtls/platform_util.h"

#include "remote_console.h"
#include "ssh_transport.h"
#include "router_config.h"
#include "wifi_config.h"
#include "vpn_config.h"
#include "web_password.h"

static const char *TAG = "remote_console";

/* NVS keys */
#define NVS_KEY_ENABLED     "rc_enabled"
#define NVS_KEY_PORT        "rc_port"
#define NVS_KEY_BIND        "rc_bind"
#define NVS_KEY_TIMEOUT     "rc_timeout"

/* Task configuration (mbedTLS ECC + esp_console_run share this stack) */
#define RC_TASK_STACK_SIZE  6144
#define RC_TASK_PRIORITY    5

/* Protocol constants */
#define RC_MAX_LINE_LEN     256
#define RC_MAX_PW_LEN       64
#define RC_MAX_AUTH_ATTEMPTS 3
#define RC_MAX_AUTH_REQUESTS 20       /* none/publickey probes included */
#define RC_AUTH_DELAY_MS    5000
#define RC_LOGIN_GRACE_MS   60000     /* handshake + authentication */
#define RC_SHUTDOWN_TIMEOUT_MS 3000
#define RC_SHUTDOWN_POLL_MS 20

/* Channel flow control: what we let the client send before a WINDOW_ADJUST */
#define RC_CHAN_WINDOW      8192
#define RC_CHAN_MAXPKT      SSH_MAX_DATA_CHUNK

static const char *RC_PROMPT = "esp32> ";
static const char *RC_WELCOME =
    "\r\nESP32 NAT Router - Remote Console (SSH)\r\n"
    "Type 'help' for commands, 'exit' to quit.\r\n\r\n";

/* State */
static remote_console_config_t rc_config = {
    .enabled = false,
    .port = REMOTE_CONSOLE_DEFAULT_PORT,
    .bind = RC_BIND_AP,
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
    /* Cleared by the task itself just before vTaskDelete(); remote_console_disable()
     * polls it, so it must not be cached in a register. */
    TaskHandle_t volatile task_handle;
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

/* Capture buffer for stdout - allocated only while a session is active */
#define RC_CAPTURE_BUF_SIZE 10240
static char *rc_capture_buf = NULL;
static size_t rc_capture_pos = 0;
static volatile bool rc_capturing = false;
/* printf from any task lands in the capture buffer while a command runs (ping
 * prints from its own task), so appends, reset and teardown are serialised. */
static portMUX_TYPE rc_capture_lock = portMUX_INITIALIZER_UNLOCKED;

/* One session channel per connection (clients may open several in sequence) */
typedef struct {
    bool open;
    bool close_sent;
    bool pty;                 /* client asked for a terminal: echo + CRLF */
    bool shell;               /* interactive shell running */
    /* A finished channel waits for the client's CLOSE, but clients may open the
     * next channel before sending it. Each channel gets its own local id and
     * the finished one is remembered as "draining", so its late CLOSE cannot
     * shut the new channel. */
    bool draining;
    uint32_t local_id;
    uint32_t draining_id;
    uint32_t peer_id;
    uint32_t peer_window;
    uint32_t peer_maxpkt;
    uint32_t consumed;        /* bytes received since the last WINDOW_ADJUST */
    /* line editor */
    char line[RC_MAX_LINE_LEN];
    size_t pos;
    uint8_t esc;              /* 0 = none, 1 = got ESC, 2 = in CSI/SS3 sequence */
    bool last_cr;
    uint8_t *in;              /* copy of received CHANNEL_DATA (rx buffer is reused) */
} rc_chan_t;

/* Forward declarations */
static void remote_console_task(void *arg);
static esp_err_t load_config(void);
static esp_err_t save_config(void);
static void handle_connection(int client_fd);

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
    if (!rc_capturing || len == 0) return;      /* cheap unlocked pre-check */

    portENTER_CRITICAL(&rc_capture_lock);
    if (rc_capturing && rc_capture_buf != NULL && rc_capture_pos < RC_CAPTURE_BUF_SIZE - 1) {
        size_t room = RC_CAPTURE_BUF_SIZE - 1 - rc_capture_pos;
        size_t copy_len = len < room ? len : room;
        memcpy(rc_capture_buf + rc_capture_pos, data, copy_len);
        rc_capture_pos += copy_len;
        rc_capture_buf[rc_capture_pos] = '\0';
    }
    portEXIT_CRITICAL(&rc_capture_lock);
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


static esp_err_t start_task(void) {
    rc_state.shutdown_requested = false;
    BaseType_t ret = xTaskCreate(remote_console_task, "remote_console",
                                 RC_TASK_STACK_SIZE, NULL,
                                 RC_TASK_PRIORITY, (TaskHandle_t *)&rc_state.task_handle);
    if (ret != pdPASS) {
        ESP_LOGE(TAG, "Failed to create remote console task");
        return ESP_ERR_NO_MEM;
    }
    rc_state.state = RC_STATE_LISTENING;
    return ESP_OK;
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
        esp_err_t err = start_task();
        if (err != ESP_OK) return err;
        ESP_LOGI(TAG, "Remote console (SSH) started on port %d", rc_config.port);
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

    rc_config.enabled = true;
    save_config();

    /* Start server if not already running */
    if (rc_state.task_handle == NULL && start_task() != ESP_OK) {
        rc_config.enabled = false;
        save_config();
        return ESP_ERR_NO_MEM;
    }

    ESP_LOGI(TAG, "Remote console (SSH) enabled on port %d", rc_config.port);
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

    /* Wait for the task to clear its own handle on the way out.  Nulling it
     * here on a fixed delay let remote_console_enable() start a second task on
     * the same port while the first was still running — and that first task
     * would then see shutdown_requested reset to false and never exit. */
    for (int waited = 0; rc_state.task_handle != NULL && waited < RC_SHUTDOWN_TIMEOUT_MS;
         waited += RC_SHUTDOWN_POLL_MS) {
        vTaskDelay(pdMS_TO_TICKS(RC_SHUTDOWN_POLL_MS));
    }
    if (rc_state.task_handle != NULL) {
        /* shutdown_requested stays set, so the task still exits on its own and
         * clears the handle.  remote_console_enable() refuses to start a second
         * task while the handle is non-NULL, so this stays safe. */
        ESP_LOGW(TAG, "Remote console task still shutting down");
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

esp_err_t remote_console_set_bind(uint8_t bind) {
    if (bind == 0) {
        bind = RC_BIND_AP;  /* Must have at least one */
    }

    rc_config.bind = bind & (RC_BIND_AP | RC_BIND_STA | RC_BIND_VPN);
    save_config();

    char bind_str[32] = "";
    if (rc_config.bind & RC_BIND_AP) strcat(bind_str, "AP ");
    if (rc_config.bind & RC_BIND_STA) strcat(bind_str, "STA ");
    if (rc_config.bind & RC_BIND_VPN) strcat(bind_str, "VPN ");
    ESP_LOGI(TAG, "Bind set to %s(restart required)", bind_str);
    return ESP_OK;
}

esp_err_t remote_console_set_timeout(uint32_t timeout_sec) {
    rc_config.idle_timeout_sec = timeout_sec;
    save_config();

    ESP_LOGI(TAG, "Idle timeout set to %lu seconds", (unsigned long)timeout_sec);
    return ESP_OK;
}

esp_err_t remote_console_kick(void) {
    if (rc_state.state != RC_STATE_ACTIVE && rc_state.state != RC_STATE_AUTH_WAIT) {
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
        strncpy(status->client_ip, rc_state.client_ip, sizeof(status->client_ip));
        int64_t now = esp_timer_get_time();
        status->session_duration_sec = (uint32_t)((now - rc_state.session_start_time) / 1000000);
        status->idle_sec = (uint32_t)((now - rc_state.last_activity_time) / 1000000);
    }

    return ESP_OK;
}

void remote_console_get_hostkey_fingerprint(char *out, size_t out_len) {
    ssh_hostkey_fingerprint(out, out_len);
}

bool remote_console_is_enabled(void) {
    return rc_config.enabled;
}

bool remote_console_session_active(void) {
    return rc_state.state == RC_STATE_ACTIVE;
}

bool remote_console_is_capturing(void) {
    return rc_capturing;
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
        /* Migrate old enum values (0=both, 1=AP, 2=STA) to bitmask */
        if (u8_val <= 2) {
            const uint8_t migrate[] = {RC_BIND_AP | RC_BIND_STA, RC_BIND_AP, RC_BIND_STA};
            rc_config.bind = migrate[u8_val];
        } else {
            rc_config.bind = u8_val & (RC_BIND_AP | RC_BIND_STA | RC_BIND_VPN);
        }
        if (rc_config.bind == 0) rc_config.bind = RC_BIND_AP;
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

static bool rc_should_abort(void) {
    return rc_state.kick_requested || rc_state.shutdown_requested;
}

/* ---- Authentication (password only, checked against the router password) ---- */

/* Failed logins are throttled across connections and services by the shared
 * backoff in cmd_router (router_login_wait_ms / router_login_result): the
 * per-connection attempt limit alone let a client reconnect and keep guessing,
 * and guesses on the web UI would otherwise not slow down SSH. */

/* Sleep, but still react to kick / disable within ~100 ms. */
static void delay_abortable(uint32_t ms) {
    while (ms > 0 && !rc_should_abort()) {
        uint32_t step = ms > 100 ? 100 : ms;
        vTaskDelay(pdMS_TO_TICKS(step));
        ms -= step;
    }
}

static esp_err_t send_auth_failure(ssh_conn_t *c) {
    ssh_out_t *o = ssh_out_begin(c, SSH_MSG_USERAUTH_FAILURE);
    ssh_put_cstr(o, "password");
    ssh_put_u8(o, 0);
    return ssh_out_send(c);
}

static bool authenticate(ssh_conn_t *c, int64_t deadline) {
    int attempts = 0;
    int requests = 0;
    bool banner_sent = false;

    for (;;) {
        int64_t left_ms = (deadline - esp_timer_get_time()) / 1000;
        if (left_ms <= 0) {
            ssh_send_disconnect(c, SSH_DISCONNECT_BY_APPLICATION, "login timeout");
            return false;
        }

        uint8_t *p;
        int n = ssh_recv(c, &p, (uint32_t)left_ms);
        if (n < 0) return false;

        ssh_in_t in;
        ssh_in_init(&in, p, n);
        uint8_t type = ssh_get_u8(&in);

        if (type == SSH_MSG_SERVICE_REQUEST) {
            if (!ssh_get_string_eq(&in, "ssh-userauth")) {
                ssh_send_disconnect(c, SSH_DISCONNECT_SERVICE_NOT_AVAILABLE, "service not available");
                return false;
            }
            ssh_out_t *o = ssh_out_begin(c, SSH_MSG_SERVICE_ACCEPT);
            ssh_put_cstr(o, "ssh-userauth");
            if (ssh_out_send(c) != ESP_OK) return false;
            continue;
        }

        if (type != SSH_MSG_USERAUTH_REQUEST) {
            if (type >= SSH_MSG_GLOBAL_REQUEST) {
                /* Connection protocol before authentication */
                ssh_send_disconnect(c, SSH_DISCONNECT_PROTOCOL_ERROR, "not authenticated");
                return false;
            }
            if (ssh_send_unimplemented(c) != ESP_OK) return false;
            continue;
        }

        if (++requests > RC_MAX_AUTH_REQUESTS) {
            ssh_send_disconnect(c, SSH_DISCONNECT_NO_MORE_AUTH_METHODS, "too many authentication requests");
            return false;
        }

        size_t user_len;
        ssh_get_string(&in, &user_len);
        bool service_ok = ssh_get_string_eq(&in, "ssh-connection");
        bool is_password = ssh_get_string_eq(&in, "password");

        if (!is_web_password_set()) {
            /* No router password: refuse every login rather than letting anyone in */
            if (!banner_sent) {
                ssh_out_t *o = ssh_out_begin(c, SSH_MSG_USERAUTH_BANNER);
                ssh_put_cstr(o, "Remote console login is disabled until a router password is set\r\n"
                                "(set_router_password on the serial console, or the web UI).\r\n");
                ssh_put_cstr(o, "");
                if (ssh_out_send(c) != ESP_OK) return false;
                banner_sent = true;
                ESP_LOGW(TAG, "SSH login from %s refused: no router password set", rc_state.client_ip);
            }
            if (send_auth_failure(c) != ESP_OK) return false;
            continue;
        }

        if (!service_ok || !is_password || in.err) {
            /* "none", "publickey", "keyboard-interactive", ...: offer password */
            if (send_auth_failure(c) != ESP_OK) return false;
            continue;
        }

        bool change = ssh_get_bool(&in);
        size_t pw_len;
        uint8_t *pw = ssh_get_string(&in, &pw_len);
        bool ok = false;

        /* Wait out a backoff from earlier failures (SSH or web UI) before
         * checking: no password is tested while the backoff runs. */
        uint32_t wait_ms = router_login_wait_ms();
        if (wait_ms > 0) {
            delay_abortable(wait_ms);
            if (rc_should_abort()) {
                if (pw) mbedtls_platform_zeroize(pw, pw_len);
                return false;
            }
        }

        if (!in.err && !change && pw_len > 0 && pw_len <= RC_MAX_PW_LEN &&
            memchr(pw, '\0', pw_len) == NULL) {
            char pw_buf[RC_MAX_PW_LEN + 1];
            memcpy(pw_buf, pw, pw_len);
            pw_buf[pw_len] = '\0';
            ok = verify_web_password(pw_buf);
            mbedtls_platform_zeroize(pw_buf, sizeof(pw_buf));
        }
        if (pw) mbedtls_platform_zeroize(pw, pw_len);

        if (ok) {
            ssh_out_begin(c, SSH_MSG_USERAUTH_SUCCESS);
            if (ssh_out_send(c) != ESP_OK) return false;
            ssh_set_authenticated(c);
            router_login_result(true);
            ESP_LOGI(TAG, "SSH login successful from %s", rc_state.client_ip);
            return true;
        }

        attempts++;
        rc_state.failed_auths++;
        uint32_t delay_ms = router_login_result(false);
        ESP_LOGW(TAG, "SSH login failed from %s (attempt %d/%d, next check in %lu ms)",
                 rc_state.client_ip, attempts, RC_MAX_AUTH_ATTEMPTS,
                 (unsigned long)delay_ms);
        if (attempts >= RC_MAX_AUTH_ATTEMPTS) {
            ssh_send_disconnect(c, SSH_DISCONNECT_NO_MORE_AUTH_METHODS, "too many authentication failures");
            /* Delay before allowing reconnection (one session slot) */
            delay_abortable(delay_ms > RC_AUTH_DELAY_MS ? delay_ms : RC_AUTH_DELAY_MS);
            return false;
        }
        delay_abortable(delay_ms);
        if (rc_should_abort()) return false;
        if (send_auth_failure(c) != ESP_OK) return false;
    }
}

/* ---- Channel helpers ---- */

static esp_err_t chan_reply(ssh_conn_t *c, rc_chan_t *ch, bool ok) {
    ssh_out_t *o = ssh_out_begin(c, ok ? SSH_MSG_CHANNEL_SUCCESS : SSH_MSG_CHANNEL_FAILURE);
    ssh_put_u32(o, ch->peer_id);
    return ssh_out_send(c);
}

/* Is the recipient channel id of a received channel message ours / the draining one? */
static bool chan_is_current(const rc_chan_t *ch, uint32_t rid) {
    return ch->open && rid == ch->local_id;
}

static bool chan_is_draining(const rc_chan_t *ch, uint32_t rid) {
    return ch->draining && rid == ch->draining_id;
}

/* Block until the client grants more window; only flow-control and teardown
 * messages are acted on, anything typed meanwhile is dropped. */
static esp_err_t chan_wait_window(ssh_conn_t *c, rc_chan_t *ch) {
    while (ch->peer_window == 0) {
        uint8_t *p;
        int n = ssh_recv(c, &p, 30000);
        if (n < 0) return ESP_FAIL;
        ssh_in_t in;
        ssh_in_init(&in, p, n);
        uint8_t type = ssh_get_u8(&in);
        uint32_t rid = ssh_get_u32(&in);
        if (in.err) continue;
        if (type == SSH_MSG_CHANNEL_CLOSE && chan_is_draining(ch, rid)) {
            ch->draining = false;      /* late CLOSE of the previous channel */
            continue;
        }
        if (!chan_is_current(ch, rid)) continue;
        if (type == SSH_MSG_CHANNEL_WINDOW_ADJUST) {
            uint32_t add = ssh_get_u32(&in);
            if (!in.err) ch->peer_window += add;
        } else if (type == SSH_MSG_CHANNEL_CLOSE || type == SSH_MSG_CHANNEL_EOF) {
            return ESP_FAIL;
        }
    }
    return ESP_OK;
}

/* Send output to the channel; with a pty, bare LF becomes CRLF. */
static esp_err_t chan_write(ssh_conn_t *c, rc_chan_t *ch, const char *data, size_t len) {
    size_t i = 0;
    while (i < len) {
        if (ch->peer_window == 0 && chan_wait_window(c, ch) != ESP_OK) return ESP_FAIL;

        size_t limit = SSH_MAX_DATA_CHUNK;
        if (limit > ch->peer_maxpkt) limit = ch->peer_maxpkt;
        if (limit > ch->peer_window) limit = ch->peer_window;
        if (limit < 2) limit = 2 > ch->peer_window ? ch->peer_window : 2;

        ssh_out_t *o = ssh_out_begin(c, SSH_MSG_CHANNEL_DATA);
        ssh_put_u32(o, ch->peer_id);
        uint8_t *len_field = ssh_put_reserve(o, 4);
        uint8_t *dst = ssh_put_reserve(o, limit);
        if (!dst) return ESP_FAIL;

        size_t out = 0;
        while (i < len && out < limit) {
            char b = data[i];
            if (ch->pty && b == '\n' && (i == 0 || data[i - 1] != '\r')) {
                if (out + 2 > limit) break;
                dst[out++] = '\r';
            }
            dst[out++] = b;
            i++;
        }
        if (out == 0) break;   /* window of 1 byte and a CRLF pending: give up */
        o->len -= (limit - out);
        len_field[0] = out >> 24; len_field[1] = out >> 16;
        len_field[2] = out >> 8;  len_field[3] = out;
        if (ssh_out_send(c) != ESP_OK) return ESP_FAIL;
        ch->peer_window -= out;
    }
    return ESP_OK;
}

static esp_err_t chan_puts(ssh_conn_t *c, rc_chan_t *ch, const char *s) {
    return chan_write(c, ch, s, strlen(s));
}

/* exit-status, EOF and CLOSE: the normal end of an exec or shell */
static void chan_finish(ssh_conn_t *c, rc_chan_t *ch, uint32_t status) {
    if (ch->close_sent) return;
    ssh_out_t *o = ssh_out_begin(c, SSH_MSG_CHANNEL_REQUEST);
    ssh_put_u32(o, ch->peer_id);
    ssh_put_cstr(o, "exit-status");
    ssh_put_u8(o, 0);
    ssh_put_u32(o, status);
    ssh_out_send(c);

    o = ssh_out_begin(c, SSH_MSG_CHANNEL_EOF);
    ssh_put_u32(o, ch->peer_id);
    ssh_out_send(c);

    o = ssh_out_begin(c, SSH_MSG_CHANNEL_CLOSE);
    ssh_put_u32(o, ch->peer_id);
    ssh_out_send(c);
    ch->close_sent = true;
    ch->shell = false;
}

/* Run one console command and send its output.  Returns the exit status. */
static uint32_t run_command(ssh_conn_t *c, rc_chan_t *ch, char *line) {
    portENTER_CRITICAL(&rc_capture_lock);
    rc_capture_pos = 0;
    rc_capture_buf[0] = '\0';
    rc_capturing = true;
    portEXIT_CRITICAL(&rc_capture_lock);

    int cmd_ret = 0;
    esp_err_t err = esp_console_run(line, &cmd_ret);

    /* Flush stdout to ensure all output is captured */
    fflush(stdout);

    /* Stop capturing - MUST happen even if command fails. Under the lock, so
     * no other task is still appending once the buffer is read below. */
    portENTER_CRITICAL(&rc_capture_lock);
    rc_capturing = false;
    portEXIT_CRITICAL(&rc_capture_lock);

    if (rc_capture_pos > 0) {
        chan_write(c, ch, rc_capture_buf, rc_capture_pos);
    }

    if (err == ESP_ERR_NOT_FOUND) {
        chan_puts(c, ch, "Unknown command. Type 'help' for list.\n");
        return 127;
    } else if (err == ESP_ERR_INVALID_ARG) {
        /* Empty or unparsable line - output already sent */
        return 1;
    } else if (err != ESP_OK) {
        char errbuf[64];
        snprintf(errbuf, sizeof(errbuf), "Error: %s\n", esp_err_to_name(err));
        chan_puts(c, ch, errbuf);
        return 1;
    }
    return (uint32_t)cmd_ret;
}

/* Feed typed bytes to the shell's line editor. */
static void shell_input(ssh_conn_t *c, rc_chan_t *ch, const uint8_t *data, size_t len) {
    char echo[64];
    size_t ne = 0;
#define ECHO(s, n) do { \
        if (ch->pty) { \
            if (ne + (n) > sizeof(echo)) { chan_write(c, ch, echo, ne); ne = 0; } \
            memcpy(echo + ne, (s), (n)); ne += (n); \
        } \
    } while (0)
#define ECHO_FLUSH() do { if (ne) { chan_write(c, ch, echo, ne); ne = 0; } } while (0)

    for (size_t i = 0; i < len && ch->shell; i++) {
        uint8_t b = data[i];

        /* Swallow escape sequences (arrow keys etc.) */
        if (ch->esc == 1) {
            ch->esc = (b == '[' || b == 'O') ? 2 : 0;
            continue;
        }
        if (ch->esc == 2) {
            if (b >= 0x40 && b <= 0x7e) ch->esc = 0;
            continue;
        }

        if (b == '\n' && ch->last_cr) {
            ch->last_cr = false;
            continue;
        }
        ch->last_cr = (b == '\r');

        if (b == '\r' || b == '\n') {
            ECHO("\r\n", 2);
            ECHO_FLUSH();
            ch->line[ch->pos] = '\0';
            size_t n = ch->pos;
            ch->pos = 0;
            rc_state.last_activity_time = esp_timer_get_time();
            if (n > 0) {
                if (strcmp(ch->line, "quit") == 0 || strcmp(ch->line, "exit") == 0) {
                    chan_puts(c, ch, "Goodbye.\n");
                    chan_finish(c, ch, 0);
                    return;
                }
                run_command(c, ch, ch->line);
            }
            chan_puts(c, ch, RC_PROMPT);
        } else if (b == 0x7f || b == 0x08) {
            if (ch->pos > 0) {
                ch->pos--;
                ECHO("\b \b", 3);
            }
        } else if (b == 0x03) {             /* Ctrl+C: discard the line */
            ECHO("^C\r\n", 4);
            ECHO_FLUSH();
            ch->pos = 0;
            chan_puts(c, ch, RC_PROMPT);
        } else if (b == 0x04) {             /* Ctrl+D on an empty line: logout */
            if (ch->pos == 0) {
                ECHO_FLUSH();
                chan_puts(c, ch, "\n");
                chan_finish(c, ch, 0);
                return;
            }
        } else if (b == 0x1b) {
            ch->esc = 1;
        } else if (b >= 0x20 && b < 0x7f) {
            if (ch->pos < sizeof(ch->line) - 1) {
                ch->line[ch->pos++] = (char)b;
                ECHO((char *)&b, 1);
            }
        }
    }
    ECHO_FLUSH();
#undef ECHO
#undef ECHO_FLUSH
}

static void handle_channel_request(ssh_conn_t *c, rc_chan_t *ch, ssh_in_t *in) {
    size_t tlen;
    uint8_t *type = ssh_get_string(in, &tlen);
    bool want_reply = ssh_get_bool(in);
    if (in->err || !ch->open || ch->close_sent) return;

#define IS(s) (tlen == sizeof(s) - 1 && memcmp(type, s, tlen) == 0)
    if (IS("pty-req")) {
        ch->pty = true;
        if (want_reply) chan_reply(c, ch, true);
    } else if (IS("shell") && !ch->shell) {
        if (want_reply) chan_reply(c, ch, true);
        ch->shell = true;
        ch->pos = 0;
        chan_puts(c, ch, RC_WELCOME);
        chan_puts(c, ch, RC_PROMPT);
    } else if (IS("exec") && !ch->shell) {
        size_t clen;
        uint8_t *cmd = ssh_get_string(in, &clen);
        if (in->err || clen >= RC_MAX_LINE_LEN) {
            if (want_reply) chan_reply(c, ch, false);
            return;
        }
        if (want_reply) chan_reply(c, ch, true);
        memcpy(ch->line, cmd, clen);
        ch->line[clen] = '\0';
        rc_state.last_activity_time = esp_timer_get_time();
        uint32_t status = run_command(c, ch, ch->line);
        chan_finish(c, ch, status);
    } else {
        /* env, window-change, subsystem (sftp), x11, agent forwarding, ... */
        if (want_reply) chan_reply(c, ch, false);
    }
#undef IS
}

/* Connection protocol after successful authentication. */
static void serve_channels(ssh_conn_t *c) {
    rc_chan_t *ch = calloc(1, sizeof(*ch));
    uint8_t *inbuf = malloc(RC_CHAN_MAXPKT);
    if (!ch || !inbuf) {
        free(ch);
        free(inbuf);
        return;
    }
    ch->in = inbuf;
    uint32_t next_id = 0;     /* local channel ids, never reused within a connection */

    while (!rc_should_abort()) {
        uint32_t timeout_ms = 0;
        if (rc_config.idle_timeout_sec > 0) {
            int64_t idle_ms = (esp_timer_get_time() - rc_state.last_activity_time) / 1000;
            int64_t left = (int64_t)rc_config.idle_timeout_sec * 1000 - idle_ms;
            timeout_ms = left > 0 ? (uint32_t)left : 1;
        }

        uint8_t *p;
        int n = ssh_recv(c, &p, timeout_ms);
        if (n == SSH_ERR_TIMEOUT) {
            if (ch->open && !ch->close_sent) {
                chan_puts(c, ch, "\nSession timeout.\n");
                chan_finish(c, ch, 0);
            }
            ssh_send_disconnect(c, SSH_DISCONNECT_BY_APPLICATION, "idle timeout");
            break;
        }
        if (n < 0) break;

        ssh_in_t in;
        ssh_in_init(&in, p, n);
        uint8_t type = ssh_get_u8(&in);

        switch (type) {
        case SSH_MSG_GLOBAL_REQUEST: {
            size_t l;
            ssh_get_string(&in, &l);
            if (ssh_get_bool(&in) && !in.err) {      /* e.g. keepalive@openssh.com */
                ssh_out_begin(c, SSH_MSG_REQUEST_FAILURE);
                ssh_out_send(c);
            }
            break;
        }
        case SSH_MSG_CHANNEL_OPEN: {
            bool session = ssh_get_string_eq(&in, "session");
            uint32_t sender = ssh_get_u32(&in);
            uint32_t window = ssh_get_u32(&in);
            uint32_t maxpkt = ssh_get_u32(&in);
            if (in.err) break;
            if (!session || (ch->open && !ch->close_sent)) {
                /* Only one shell/exec session at a time; no port forwarding
                 * through the router */
                ssh_out_t *o = ssh_out_begin(c, SSH_MSG_CHANNEL_OPEN_FAILURE);
                ssh_put_u32(o, sender);
                ssh_put_u32(o, 1);                   /* administratively prohibited */
                ssh_put_cstr(o, "only one session channel is supported");
                ssh_put_cstr(o, "");
                ssh_out_send(c);
                break;
            }
            /* A finished channel still waiting for the client's CLOSE becomes
             * the draining one; otherwise keep any earlier draining state. */
            bool draining = ch->open ? true : ch->draining;
            uint32_t draining_id = ch->open ? ch->local_id : ch->draining_id;
            memset(ch, 0, sizeof(*ch));
            ch->in = inbuf;
            ch->open = true;
            ch->local_id = next_id++;
            ch->draining = draining;
            ch->draining_id = draining_id;
            ch->peer_id = sender;
            ch->peer_window = window;
            ch->peer_maxpkt = maxpkt ? maxpkt : 1;
            ssh_out_t *o = ssh_out_begin(c, SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
            ssh_put_u32(o, sender);
            ssh_put_u32(o, ch->local_id);            /* our channel id */
            ssh_put_u32(o, RC_CHAN_WINDOW);
            ssh_put_u32(o, RC_CHAN_MAXPKT);
            ssh_out_send(c);
            break;
        }
        case SSH_MSG_CHANNEL_REQUEST:
            /* Requests for the draining or an unknown channel are dropped */
            if (chan_is_current(ch, ssh_get_u32(&in)) && !in.err) {
                handle_channel_request(c, ch, &in);
            }
            break;
        case SSH_MSG_CHANNEL_WINDOW_ADJUST: {
            uint32_t rid = ssh_get_u32(&in);
            uint32_t add = ssh_get_u32(&in);
            if (!in.err && chan_is_current(ch, rid)) {
                ch->peer_window = (ch->peer_window + add < ch->peer_window)
                                  ? UINT32_MAX : ch->peer_window + add;
            }
            break;
        }
        case SSH_MSG_CHANNEL_DATA: {
            uint32_t rid = ssh_get_u32(&in);
            size_t dlen;
            uint8_t *data = ssh_get_string(&in, &dlen);
            if (in.err || !chan_is_current(ch, rid) || ch->close_sent) break;
            if (dlen > RC_CHAN_MAXPKT) dlen = RC_CHAN_MAXPKT;
            ch->consumed += dlen;
            if (ch->consumed >= RC_CHAN_WINDOW / 2) {
                ssh_out_t *o = ssh_out_begin(c, SSH_MSG_CHANNEL_WINDOW_ADJUST);
                ssh_put_u32(o, ch->peer_id);
                ssh_put_u32(o, ch->consumed);
                ssh_out_send(c);
                ch->consumed = 0;
            }
            if (ch->shell) {
                /* Commands send packets (and may read some while waiting for
                 * window), which reuses the rx buffer: work on a copy. */
                memcpy(ch->in, data, dlen);
                shell_input(c, ch, ch->in, dlen);
            }
            break;
        }
        case SSH_MSG_CHANNEL_EXTENDED_DATA:
            break;
        case SSH_MSG_CHANNEL_EOF:
            if (chan_is_current(ch, ssh_get_u32(&in)) && !in.err && ch->shell) {
                chan_finish(c, ch, 0);
            }
            break;
        case SSH_MSG_CHANNEL_CLOSE: {
            uint32_t rid = ssh_get_u32(&in);
            if (in.err) break;
            if (chan_is_draining(ch, rid)) {
                /* Late CLOSE of the previous channel; ours went out already */
                ch->draining = false;
                break;
            }
            if (chan_is_current(ch, rid)) {
                if (!ch->close_sent) {
                    ssh_out_t *o = ssh_out_begin(c, SSH_MSG_CHANNEL_CLOSE);
                    ssh_put_u32(o, ch->peer_id);
                    ssh_out_send(c);
                }
                ch->open = false;
                ch->close_sent = false;
                ch->shell = false;
            }
            break;
        }
        default:
            ssh_send_unimplemented(c);
            break;
        }
    }

    if (rc_state.kick_requested || rc_state.shutdown_requested) {
        ssh_send_disconnect(c, SSH_DISCONNECT_BY_APPLICATION, "session terminated by administrator");
    }
    mbedtls_platform_zeroize(ch, sizeof(*ch));
    free(ch);
    free(inbuf);
}

static void handle_connection(int client_fd) {
    rc_state.state = RC_STATE_AUTH_WAIT;
    rc_state.kick_requested = false;

    int64_t deadline = esp_timer_get_time() + (int64_t)RC_LOGIN_GRACE_MS * 1000;
    ssh_conn_t *c = ssh_conn_new(client_fd, rc_should_abort);
    if (c == NULL) {
        ESP_LOGE(TAG, "Out of memory for SSH session");
        return;
    }

    if (ssh_handshake(c, RC_LOGIN_GRACE_MS) != ESP_OK) {
        ESP_LOGW(TAG, "SSH handshake with %s failed", rc_state.client_ip);
        ssh_conn_free(c);
        return;
    }

    if (authenticate(c, deadline)) {
        rc_capture_buf = malloc(RC_CAPTURE_BUF_SIZE);
        if (rc_capture_buf == NULL) {
            ESP_LOGE(TAG, "Failed to allocate capture buffer");
        } else {
            rc_state.state = RC_STATE_ACTIVE;
            rc_state.session_start_time = esp_timer_get_time();
            rc_state.last_activity_time = rc_state.session_start_time;
            ESP_LOGI(TAG, "Session started with %s", rc_state.client_ip);

            serve_channels(c);

            portENTER_CRITICAL(&rc_capture_lock);
            rc_capturing = false;
            char *buf = rc_capture_buf;
            rc_capture_buf = NULL;
            rc_capture_pos = 0;
            portEXIT_CRITICAL(&rc_capture_lock);
            free(buf);
            ESP_LOGI(TAG, "Session ended with %s (stack headroom %u bytes)",
                     rc_state.client_ip, (unsigned)uxTaskGetStackHighWaterMark(NULL));
        }
    }

    ssh_conn_free(c);
}

static void remote_console_task(void *arg) {
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len;
    int opt = 1;

    ESP_LOGI(TAG, "Remote console task started");

    /* Load (or on first use generate) the SSH host key here rather than in the
     * caller: key generation needs more stack than HTTP/MQTT handlers have. */
    while (!rc_state.shutdown_requested && ssh_hostkey_init() != ESP_OK) {
        vTaskDelay(pdMS_TO_TICKS(5000));
    }
    if (!rc_state.shutdown_requested) {
        char fp[64];
        ssh_hostkey_fingerprint(fp, sizeof(fp));
        ESP_LOGI(TAG, "SSH host key %s", fp);
    }

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
        server_addr.sin_addr.s_addr = htonl(INADDR_ANY);  /* Filtered per-connection by rc_config.bind */

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
        ESP_LOGI(TAG, "SSH listening on port %d", rc_config.port);

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

            /* Check interface binding - reject connections on disallowed interfaces.
             * Keying on the local address is sufficient: lwIP accepts packets for
             * any of its addresses on any interface, but ESP-IDF's source-based
             * routing hook sends the replies out of the interface owning that
             * address, so e.g. an upstream host targeting the AP address cannot
             * complete the TCP handshake (verified on hardware). */
            {
                struct sockaddr_in local_addr;
                socklen_t addr_len = sizeof(local_addr);
                getsockname(rc_state.client_socket, (struct sockaddr *)&local_addr, &addr_len);
                uint32_t local_ip = local_addr.sin_addr.s_addr;

                bool allowed = false;
                if ((rc_config.bind & RC_BIND_AP) && local_ip == my_ap_ip) allowed = true;
                if ((rc_config.bind & RC_BIND_STA) && local_ip == my_ip) allowed = true;
                if ((rc_config.bind & RC_BIND_VPN) && vpn_connected && vpn_address && vpn_address[0]) {
                    ip4_addr_t vpn_addr;
                    if (ip4addr_aton(vpn_address, &vpn_addr) && local_ip == vpn_addr.addr) {
                        allowed = true;
                    }
                }

                if (!allowed) {
                    ESP_LOGW(TAG, "Connection from %s rejected (interface not allowed)", rc_state.client_ip);
                    close(rc_state.client_socket);
                    rc_state.client_socket = -1;
                    continue;
                }
            }

            rc_state.total_connections++;
            ESP_LOGI(TAG, "Connection from %s", rc_state.client_ip);

            /* Try to acquire session mutex */
            if (xSemaphoreTake(rc_state.session_mutex, 0) != pdTRUE) {
                close(rc_state.client_socket);
                rc_state.client_socket = -1;
                continue;
            }

            handle_connection(rc_state.client_socket);

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
