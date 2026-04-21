#pragma once

#include "sdkconfig.h"

#if CONFIG_REPEATER_MODE

#include <stdbool.h>
#include "lwip/pbuf.h"
#include "lwip/netif.h"

void repeater_forward_init(void);

/* Register the AP and STA lwIP netifs so the forwarder can re-emit frames.
 * May be called once both netifs are ready; either netif may be NULL until
 * its side of the wifi mode is up. */
void repeater_forward_set_netifs(struct netif *ap, struct netif *sta);

/* Hook entry points called from netif_hooks.c when REPEATER_MODE is on.
 * Return true if the packet has been consumed (forwarded or dropped) and
 * must not be delivered to the original netif input path; false to let
 * the original path run (packet is for ESP32 itself). */
bool repeater_ap_rx_handle(struct pbuf *p, struct netif *ap_netif);
bool repeater_sta_rx_handle(struct pbuf *p, struct netif *sta_netif);

#endif
