/**
 * @file remote_console.h
 * @brief Secure remote console for ESP32 NAT Router
 *
 * Provides network-accessible CLI with password authentication.
 * Phase 1: Plain TCP (TLS to be added in Phase 2)
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Default TCP port for remote console */
#define REMOTE_CONSOLE_DEFAULT_PORT     2323

/** Default idle timeout in seconds */
#define REMOTE_CONSOLE_DEFAULT_TIMEOUT  300

/** Interface binding options */
typedef enum {
    RC_BIND_BOTH = 0,   /**< Listen on both AP and STA interfaces */
    RC_BIND_AP_ONLY,    /**< Listen only on AP interface */
    RC_BIND_STA_ONLY    /**< Listen only on STA interface */
} remote_console_bind_t;

/** Session state */
typedef enum {
    RC_STATE_DISABLED,      /**< Service disabled */
    RC_STATE_LISTENING,     /**< Waiting for connection */
    RC_STATE_AUTH_WAIT,     /**< Waiting for password */
    RC_STATE_ACTIVE,        /**< Session active */
} remote_console_state_t;

/** Remote console configuration */
typedef struct {
    bool enabled;                   /**< Service enabled */
    uint16_t port;                  /**< TCP port */
    remote_console_bind_t bind;     /**< Interface binding */
    uint32_t idle_timeout_sec;      /**< Idle timeout in seconds */
} remote_console_config_t;

/** Remote console status */
typedef struct {
    remote_console_state_t state;   /**< Current state */
    char client_ip[16];             /**< Connected client IP (if active) */
    uint32_t session_duration_sec;  /**< Current session duration */
    uint32_t idle_sec;              /**< Seconds since last command */
    uint32_t total_connections;     /**< Total connections since boot */
    uint32_t failed_auths;          /**< Failed authentication attempts */
} remote_console_status_t;

/**
 * @brief Initialize remote console subsystem
 *
 * Loads configuration from NVS and starts server if enabled.
 * Should be called once during startup.
 *
 * @return ESP_OK on success
 */
esp_err_t remote_console_init(void);

/**
 * @brief Enable remote console service
 *
 * Saves state to NVS and starts the server.
 *
 * @return ESP_OK on success
 */
esp_err_t remote_console_enable(void);

/**
 * @brief Disable remote console service
 *
 * Saves state to NVS, disconnects any active session, and stops server.
 *
 * @return ESP_OK on success
 */
esp_err_t remote_console_disable(void);

/**
 * @brief Set TCP port
 *
 * @param port TCP port number (1-65535)
 * @return ESP_OK on success, ESP_ERR_INVALID_ARG if port invalid
 * @note Requires restart to take effect if service is running
 */
esp_err_t remote_console_set_port(uint16_t port);

/**
 * @brief Set interface binding
 *
 * @param bind Interface binding option
 * @return ESP_OK on success
 * @note Requires restart to take effect if service is running
 */
esp_err_t remote_console_set_bind(remote_console_bind_t bind);

/**
 * @brief Set idle timeout
 *
 * @param timeout_sec Timeout in seconds (0 = no timeout)
 * @return ESP_OK on success
 */
esp_err_t remote_console_set_timeout(uint32_t timeout_sec);

/**
 * @brief Disconnect current session (kick)
 *
 * @return ESP_OK if session was disconnected, ESP_ERR_NOT_FOUND if no active session
 */
esp_err_t remote_console_kick(void);

/**
 * @brief Get current configuration
 *
 * @param config Pointer to config structure to fill
 * @return ESP_OK on success
 */
esp_err_t remote_console_get_config(remote_console_config_t *config);

/**
 * @brief Get current status
 *
 * @param status Pointer to status structure to fill
 * @return ESP_OK on success
 */
esp_err_t remote_console_get_status(remote_console_status_t *status);

/**
 * @brief Check if remote console is enabled
 *
 * @return true if enabled
 */
bool remote_console_is_enabled(void);

/**
 * @brief Check if a session is currently active
 *
 * @return true if session active
 */
bool remote_console_session_active(void);

/**
 * @brief Check if output is being captured for a remote console session
 *
 * @return true if a command is executing via remote console
 */
bool remote_console_is_capturing(void);

#ifdef __cplusplus
}
#endif
