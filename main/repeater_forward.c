#include "repeater_forward.h"

#if CONFIG_REPEATER_MODE

#include <string.h>
#include <inttypes.h>
#include "esp_log.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/prot/ip4.h"
#include "fdb.h"
#include "dhcp_xid_map.h"
#include "dhcp_helpers.h"
#include "dhcp_lease_map.h"
#include "repeater_config.h"

static const char *TAG = "repeater_fwd";

static struct netif *s_ap_netif  = NULL;
static struct netif *s_sta_netif = NULL;

#define ETYPE_IP4  0x0800
#define ETYPE_ARP  0x0806

void repeater_forward_init(void) {
    fdb_init();
    dhcp_xid_map_init();
    dhcp_lease_map_init();
    ESP_LOGI(TAG, "Repeater forwarding initialized");
}

void repeater_forward_set_netifs(struct netif *ap, struct netif *sta) {
    if (ap)  s_ap_netif  = ap;
    if (sta) s_sta_netif = sta;
    ESP_LOGI(TAG, "netifs ap=%p sta=%p", s_ap_netif, s_sta_netif);
}

/* ---- DHCP snooping helpers ---- */

static const uint8_t *locate_dhcp(const uint8_t *eth, size_t len,
                                  uint16_t want_sport, uint16_t want_dport,
                                  size_t *dhcp_len_out) {
    if (len < 14 + 20 + 8 + 240) return NULL;
    if (eth[12] != 0x08 || eth[13] != 0x00) return NULL;
    const struct ip_hdr *iphdr = (const struct ip_hdr *)(eth + 14);
    if (IPH_V(iphdr) != 4) return NULL;
    uint8_t ihl = IPH_HL(iphdr) * 4;
    if (ihl < 20 || len < 14u + ihl + 8 + 240) return NULL;
    if (IPH_PROTO(iphdr) != 17 /* UDP */) return NULL;
    const uint8_t *udp = eth + 14 + ihl;
    uint16_t sport = ((uint16_t)udp[0] << 8) | udp[1];
    uint16_t dport = ((uint16_t)udp[2] << 8) | udp[3];
    if (sport != want_sport || dport != want_dport) return NULL;
    const uint8_t *dhcp = udp + 8;
    *dhcp_len_out = len - (size_t)(dhcp - eth);
    return dhcp;
}

static void snoop_dhcp_client(const uint8_t *eth, size_t len) {
    size_t dlen = 0;
    const uint8_t *dhcp = locate_dhcp(eth, len, 68, 67, &dlen);
    if (!dhcp) return;
    dhcp_parsed_t info;
    if (!dhcp_parse(dhcp, dlen, &info)) return;
    if (info.op != DHCP_BOOTP_REQUEST) return;
    dhcp_xid_map_insert(info.xid, info.chaddr);
    if (info.hostname[0]) {
        dhcp_lease_map_set_hostname(info.chaddr, info.hostname);
    }
    ESP_LOGD(TAG, "DHCP client xid=0x%08" PRIx32 " type=%u host=%s",
             info.xid, info.msg_type, info.hostname[0] ? info.hostname : "-");
}

static void snoop_dhcp_server_reply(const uint8_t *eth, size_t len, uint8_t chaddr_out[6]) {
    size_t dlen = 0;
    const uint8_t *dhcp = locate_dhcp(eth, len, 67, 68, &dlen);
    if (!dhcp) { if (chaddr_out) memset(chaddr_out, 0, 6); return; }
    dhcp_parsed_t info;
    if (!dhcp_parse(dhcp, dlen, &info) || info.op != DHCP_BOOTP_REPLY) {
        if (chaddr_out) memset(chaddr_out, 0, 6);
        return;
    }
    if (chaddr_out) memcpy(chaddr_out, info.chaddr, 6);
    if (info.msg_type == DHCPACK && info.yiaddr != 0) {
        fdb_learn(info.yiaddr, info.chaddr, REPEATER_FDB_DEFAULT_TTL_S);
        dhcp_lease_map_update(info.chaddr, info.yiaddr,
                              info.hostname[0] ? info.hostname : NULL,
                              info.lease_time);
    }
}

/* ---- MAC translation forwarding ---- */

static bool mac_is_broadcast(const uint8_t m[6]) {
    return m[0] == 0xff && m[1] == 0xff && m[2] == 0xff &&
           m[3] == 0xff && m[4] == 0xff && m[5] == 0xff;
}

/* Emit a pbuf out the given netif via its (hooked) linkoutput. */
static bool emit_on(struct netif *nif, struct pbuf *p) {
    if (!nif || !nif->linkoutput) return false;
    err_t r = nif->linkoutput(nif, p);
    return r == ERR_OK;
}

/* AP→STA bridge: rewrite L2 src MAC to STA MAC; for ARP also rewrite
 * ARP sender HA so replies return to STA. Consumes the pbuf on success. */
static bool bridge_ap_to_sta(struct pbuf *p) {
    if (!s_sta_netif) return false;
    if (p->len < 14) return false;

    uint8_t *eth = (uint8_t *)p->payload;
    uint16_t etype = ((uint16_t)eth[12] << 8) | eth[13];
    const uint8_t *sta_mac = s_sta_netif->hwaddr;

    if (etype == ETYPE_ARP) {
        if (p->len < 14 + 28) return false;
        uint8_t *arp = eth + 14;
        /* ARP layout: htype(2) ptype(2) hlen(1) plen(1) oper(2)
         *             sha(6) spa(4) tha(6) tpa(4) */
        uint16_t oper = ((uint16_t)arp[6] << 8) | arp[7];
        uint32_t tpa;
        memcpy(&tpa, arp + 24, 4);
        uint32_t sta_ip = s_sta_netif->ip_addr.u_addr.ip4.addr;

        /* Proxy ARP: if an AP client asks "who has <STA IP>?", reply
         * directly with the AP MAC so packets to the management IP
         * arrive on the AP netif and can be routed to the STA stack. */
        if (oper == 1 && sta_ip && tpa == sta_ip && s_ap_netif) {
            const uint8_t *ap_mac = s_ap_netif->hwaddr;
            uint8_t req_sha[6];
            uint32_t req_spa;
            memcpy(req_sha, arp + 8,  6);   /* sender MAC */
            memcpy(&req_spa, arp + 14, 4);  /* sender IP  */

            /* Build ARP reply in-place */
            memcpy(eth + 0, req_sha, 6);    /* Ethernet dst = requester */
            memcpy(eth + 6, ap_mac,  6);    /* Ethernet src = AP MAC    */
            arp[6] = 0; arp[7] = 2;         /* oper = reply             */
            memcpy(arp + 8,  ap_mac,  6);   /* sha  = AP MAC            */
            memcpy(arp + 14, &tpa,    4);   /* spa  = requested IP      */
            memcpy(arp + 18, req_sha, 6);   /* tha  = requester MAC     */
            memcpy(arp + 24, &req_spa, 4);  /* tpa  = requester IP      */

            emit_on(s_ap_netif, p);
            pbuf_free(p);
            return true;
        }

        /* All other ARP: forward upstream with STA MAC */
        memcpy(arp + 8, sta_mac, 6);   /* sender HA */
        memcpy(eth + 6, sta_mac, 6);   /* L2 src */
        emit_on(s_sta_netif, p);
        pbuf_free(p);
        return true;
    }

    if (etype == ETYPE_IP4) {
        if (p->len < 14 + 20) return false;
        /* Snoop DHCP client requests before rewriting */
        snoop_dhcp_client(eth, p->len);
        /* Learn src IP ↔ client MAC so we can route replies back */
        const struct ip_hdr *iphdr = (const struct ip_hdr *)(eth + 14);
        if (IPH_V(iphdr) != 4) return false;
        if (iphdr->src.addr != 0) {
            fdb_learn(iphdr->src.addr, eth + 6, REPEATER_FDB_DEFAULT_TTL_S);
        }
        uint32_t ap_ip  = s_ap_netif  ? s_ap_netif->ip_addr.u_addr.ip4.addr  : 0;
        uint32_t sta_ip = s_sta_netif ? s_sta_netif->ip_addr.u_addr.ip4.addr : 0;

        /* Packets destined for the AP IP are handled by the AP netif's own stack. */
        if (ap_ip && iphdr->dest.addr == ap_ip) {
            return false;
        }

        /* Packets destined for the STA (management) IP: the AP netif's lwIP
         * stack doesn't know this address, so inject directly into the STA
         * netif's input with the dst MAC rewritten to the STA MAC. */
        if (sta_ip && iphdr->dest.addr == sta_ip && s_sta_netif->input) {
            memcpy(eth + 0, sta_mac, 6);
            s_sta_netif->input(p, s_sta_netif);
            return true;
        }

        memcpy(eth + 6, sta_mac, 6);
        emit_on(s_sta_netif, p);
        pbuf_free(p);
        return true;
    }

    return false;
}

/* STA→AP bridge: resolve the intended client via FDB (or DHCP chaddr for
 * DHCP replies), rewrite L2 src to AP MAC and L2 dst to client MAC.
 * Returns true if the packet was forwarded/consumed. */
static bool bridge_sta_to_ap(struct pbuf *p) {
    if (!s_ap_netif) return false;
    if (p->len < 14) return false;

    uint8_t *eth = (uint8_t *)p->payload;
    uint16_t etype = ((uint16_t)eth[12] << 8) | eth[13];
    const uint8_t *ap_mac = s_ap_netif->hwaddr;

    /* Don't re-forward broadcasts that originated from our own AP MAC */
    if (memcmp(eth + 6, ap_mac, 6) == 0) return false;

    if (etype == ETYPE_ARP) {
        if (p->len < 14 + 28) return false;
        uint8_t *arp = eth + 14;
        uint32_t tpa;
        memcpy(&tpa, arp + 24, 4); /* target protocol address */
        uint8_t client_mac[6];
        if (!fdb_lookup_by_ip(tpa, client_mac)) {
            /* Broadcast ARP request from upstream — flood to AP unchanged src */
            if (mac_is_broadcast(eth)) {
                memcpy(eth + 6, ap_mac, 6);
                emit_on(s_ap_netif, p);
                pbuf_free(p);
                return true;
            }
            return false;
        }
        memcpy(arp + 18, client_mac, 6);  /* target HA in ARP body */
        memcpy(eth + 0, client_mac, 6);   /* L2 dst */
        memcpy(eth + 6, ap_mac, 6);       /* L2 src */
        emit_on(s_ap_netif, p);
        pbuf_free(p);
        return true;
    }

    if (etype == ETYPE_IP4) {
        if (p->len < 14 + 20) return false;
        const struct ip_hdr *iphdr = (const struct ip_hdr *)(eth + 14);
        if (IPH_V(iphdr) != 4) return false;

        /* If destined to ESP32 itself (STA or AP IP), consume locally. */
        uint32_t ap_ip  = s_ap_netif  ? s_ap_netif->ip_addr.u_addr.ip4.addr  : 0;
        uint32_t sta_ip = s_sta_netif ? s_sta_netif->ip_addr.u_addr.ip4.addr : 0;
        if ((sta_ip && iphdr->dest.addr == sta_ip) ||
            (ap_ip  && iphdr->dest.addr == ap_ip)) {
            return false;
        }

        uint8_t client_mac[6] = {0};
        bool have_client = false;

        /* DHCP reply: derive client MAC from packet (chaddr) and learn FDB */
        snoop_dhcp_server_reply(eth, p->len, client_mac);
        if (client_mac[0] | client_mac[1] | client_mac[2] |
            client_mac[3] | client_mac[4] | client_mac[5]) {
            have_client = true;
        }

        if (!have_client) {
            if (fdb_lookup_by_ip(iphdr->dest.addr, client_mac)) {
                have_client = true;
            }
        }

        if (!have_client) {
            /* Broadcast IPv4 (e.g. mDNS, NBNS) — flood to AP */
            if (mac_is_broadcast(eth)) {
                memcpy(eth + 6, ap_mac, 6);
                emit_on(s_ap_netif, p);
                pbuf_free(p);
                return true;
            }
            return false;
        }

        memcpy(eth + 0, client_mac, 6);
        memcpy(eth + 6, ap_mac, 6);
        emit_on(s_ap_netif, p);
        pbuf_free(p);
        return true;
    }

    return false;
}

bool repeater_ap_rx_handle(struct pbuf *p, struct netif *ap_netif) {
    (void)ap_netif;
    if (!p) return false;
    return bridge_ap_to_sta(p);
}

bool repeater_sta_rx_handle(struct pbuf *p, struct netif *sta_netif) {
    (void)sta_netif;
    if (!p) return false;
    return bridge_sta_to_ap(p);
}

#endif
