/* Port mapping (NAT port forwarding) table and management.
 *
 * SPDX-License-Identifier: MIT
 */
#pragma once

#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

struct portmap_table_entry {
    uint32_t daddr;
    uint16_t mport;
    uint16_t dport;
    uint8_t proto;
    uint8_t valid;
    uint8_t iface;       // 0=STA/ETH (uplink), 1=VPN
};

extern struct portmap_table_entry portmap_tab[];

void print_portmap_tab(void);
esp_err_t get_portmap_tab(void);
esp_err_t apply_portmap_tab(void);
esp_err_t delete_portmap_tab(void);
esp_err_t add_portmap(uint8_t proto, uint16_t mport, uint32_t daddr, uint16_t dport, uint8_t iface);
esp_err_t del_portmap(uint8_t proto, uint16_t mport);
esp_err_t clear_all_portmaps(void);

#ifdef __cplusplus
}
#endif
