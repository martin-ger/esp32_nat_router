/* Web interface password management and captive DNS.
 *
 * SPDX-License-Identifier: MIT
 */
#pragma once

#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

// Password hashing (SHA-256 + salt)
// Returns true if a non-empty password is stored in NVS.
bool is_web_password_set(void);
// Verify a plaintext password against the stored hash. Returns true on match.
bool verify_web_password(const char *plaintext);
// Hash and store a new password (empty string disables protection).
esp_err_t set_web_password_hashed(const char *plaintext);

// Failed-login backoff shared by every login path (web UI and SSH), so that
// guessing on one service cannot bypass the throttling of the other.
// After a failure the next attempt is held off for 1 s, doubling every 3
// consecutive failures up to 30 s; reset on success or after 15 quiet min.
//
// Milliseconds until the next login attempt may be checked (0 = now).
uint32_t router_login_wait_ms(void);
// Record the outcome of a password check; returns the new wait in ms.
uint32_t router_login_result(bool success);

#ifdef __cplusplus
}
#endif
