#pragma once

#include "sdkconfig.h"

#if CONFIG_REPEATER_MODE

#include <stdbool.h>
#include "lwip/pbuf.h"
#include "lwip/netif.h"

/* Inspect an AP-side IPv4 frame; if it is an mDNS query for our hostname.local
 * (A or ANY), build and emit a multicast A-record reply directly on the AP via
 * ap_netif->linkoutput. The query is left untouched and continues through the
 * bridge so upstream responders can still reply too. */
void mdns_responder_handle_ap_query(struct pbuf *p, struct netif *ap_netif,
                                    struct netif *sta_netif);

#endif
