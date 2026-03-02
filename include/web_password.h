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

#ifdef __cplusplus
}
#endif
