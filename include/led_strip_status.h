/* Addressable LED strip (WS2812 / SK6812) status indicator.
 *
 * Drives a single addressable LED to show router state via color:
 *   Red          — not connected to upstream AP
 *   Yellow pulse — connecting
 *   Green        — connected (brightness scales with client count)
 *   White flash  — traffic burst
 *   Red/blue     — factory-reset hold
 *
 * Configured via NVS key "ls_gpio" (-1 = disabled, default).
 * Mutually exclusive with the plain GPIO LED (led_gpio).
 *
 * SPDX-License-Identifier: MIT
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* NVS key for LED strip GPIO (-1 = disabled) */
extern int led_strip_gpio;

/**
 * Initialise the LED strip driver.
 * Call once from app_main() after loading led_strip_gpio from NVS.
 * Does nothing if led_strip_gpio < 0.
 */
void led_strip_status_init(void);

/**
 * Notify the strip of a traffic event (packet sent or received).
 * Safe to call from any context (ISR-safe flag set, rendered in status thread).
 */
void led_strip_notify_traffic(void);

/**
 * Set factory-reset visual mode (rapid red/blue alternation).
 * The status thread picks this up on its next cycle.
 */
void led_strip_set_factory_reset(bool active);

/**
 * Returns true if the LED strip driver is active.
 */
bool led_strip_is_active(void);

/**
 * Update LED strip colour based on current router state.
 * Called from the led_status_thread at ~50 ms intervals.
 */
void led_strip_status_update(void);

#ifdef __cplusplus
}
#endif
