#include "mdns_responder.h"

#if CONFIG_REPEATER_MODE

#include <ctype.h>
#include <string.h>
#include "esp_log.h"
#include "lwip/prot/ip4.h"
#include "lwip/inet_chksum.h"

/* Hostname configured on the STA netif; same string the SDK mDNS uses. */
extern char *hostname;

static const char *TAG = "mdns_resp";

#define MDNS_PORT 5353
#define MDNS_MCAST_IP4   0xFB0000E0u  /* 224.0.0.251 in network byte order */

static bool ieq(uint8_t a, uint8_t b) {
    if (a >= 'A' && a <= 'Z') a = (uint8_t)(a + 32);
    if (b >= 'A' && b <= 'Z') b = (uint8_t)(b + 32);
    return a == b;
}

/* Walk a DNS-encoded name from 'qn', matching it case-insensitively against
 * "<host>.local". Returns the byte count consumed on success, 0 otherwise. */
static size_t match_hostname_local(const uint8_t *qn, size_t avail,
                                   const char *host) {
    size_t host_len = strlen(host);
    size_t i = 0;
    if (i >= avail) return 0;
    uint8_t l = qn[i++];
    if (l == 0 || l > 63) return 0;
    if (l != host_len) return 0;
    if (i + l > avail) return 0;
    for (size_t k = 0; k < l; k++) {
        if (!ieq(qn[i + k], (uint8_t)host[k])) return 0;
    }
    i += l;
    if (i >= avail) return 0;
    l = qn[i++];
    if (l != 5) return 0;
    if (i + l > avail) return 0;
    static const char local_s[5] = { 'l','o','c','a','l' };
    for (size_t k = 0; k < l; k++) {
        if (!ieq(qn[i + k], (uint8_t)local_s[k])) return 0;
    }
    i += l;
    if (i >= avail || qn[i] != 0) return 0;
    return i + 1;
}

void mdns_responder_handle_ap_query(struct pbuf *p, struct netif *ap_netif,
                                    struct netif *sta_netif) {
    if (!p || !ap_netif || !sta_netif || !hostname || !*hostname) return;
    if (p->len < 14 + 20 + 8 + 12) return;
    const uint8_t *eth = (const uint8_t *)p->payload;
    if (eth[12] != 0x08 || eth[13] != 0x00) return;
    const struct ip_hdr *iphdr = (const struct ip_hdr *)(eth + 14);
    if (IPH_V(iphdr) != 4 || IPH_PROTO(iphdr) != 17) return;
    uint8_t ihl = IPH_HL(iphdr) * 4;
    if (p->len < 14u + ihl + 8 + 12) return;
    const uint8_t *udp = eth + 14 + ihl;
    uint16_t sport = ((uint16_t)udp[0] << 8) | udp[1];
    uint16_t dport = ((uint16_t)udp[2] << 8) | udp[3];
    if (dport != MDNS_PORT) return;

    const uint8_t *dns = udp + 8;
    size_t dns_len = p->len - 14u - ihl - 8;
    if (dns_len < 12) return;
    if (dns[2] & 0x80) return;                /* must be a query */
    uint16_t qd = ((uint16_t)dns[4] << 8) | dns[5];
    if (qd == 0 || qd > 8) return;

    bool matched = false;
    bool unicast_response = false;
    size_t off = 12;
    for (uint16_t i = 0; i < qd; i++) {
        size_t consumed = match_hostname_local(dns + off, dns_len - off, hostname);
        if (consumed == 0) {
            size_t k = off;
            while (k < dns_len && dns[k] != 0) {
                if ((dns[k] & 0xC0) == 0xC0) { k += 2; goto type_class; }
                if (dns[k] > 63) return;
                k += 1 + dns[k];
            }
            if (k >= dns_len) return;
            k += 1;
type_class:
            if (k + 4 > dns_len) return;
            off = k + 4;
            continue;
        }
        size_t qend = off + consumed;
        if (qend + 4 > dns_len) return;
        uint16_t qtype  = ((uint16_t)dns[qend] << 8) | dns[qend + 1];
        uint16_t qclass = ((uint16_t)dns[qend + 2] << 8) | dns[qend + 3];
        if (qtype == 1 /* A */ || qtype == 255 /* ANY */) {
            matched = true;
            /* Top bit of qclass = QU: querier wants unicast reply. */
            if (qclass & 0x8000) unicast_response = true;
            break;
        }
        off = qend + 4;
    }
    if (!matched) return;

    uint32_t sta_ip = sta_netif->ip_addr.u_addr.ip4.addr;
    if (!sta_ip) return;

    size_t host_len = strlen(hostname);
    if (host_len == 0 || host_len > 63) return;
    size_t name_len   = 1 + host_len + 1 + 5 + 1;
    size_t answer_len = name_len + 2 + 2 + 4 + 2 + 4;
    size_t dns_total  = 12 + answer_len;
    size_t udp_total  = 8 + dns_total;
    size_t ip_total   = 20 + udp_total;
    size_t frame_len  = 14 + ip_total;

    struct pbuf *resp = pbuf_alloc(PBUF_RAW, frame_len, PBUF_RAM);
    if (!resp) return;

    uint8_t *buf = (uint8_t *)resp->payload;
    memset(buf, 0, frame_len);

    /* Ethernet + IP destination depend on QU bit. */
    if (unicast_response) {
        memcpy(buf + 0, eth + 6, 6);                      /* dst MAC = querier */
    } else {
        /* mDNS multicast: 01:00:5e:00:00:fb */
        buf[0] = 0x01; buf[1] = 0x00; buf[2] = 0x5e;
        buf[3] = 0x00; buf[4] = 0x00; buf[5] = 0xfb;
    }
    memcpy(buf + 6, ap_netif->hwaddr, 6);
    buf[12] = 0x08; buf[13] = 0x00;

    struct ip_hdr *rip = (struct ip_hdr *)(buf + 14);
    IPH_VHL_SET(rip, 4, 5);
    IPH_TOS_SET(rip, 0);
    IPH_LEN_SET(rip, lwip_htons((uint16_t)ip_total));
    IPH_ID_SET(rip, 0);
    IPH_OFFSET_SET(rip, 0);
    IPH_TTL_SET(rip, 255);
    IPH_PROTO_SET(rip, 17);
    IPH_CHKSUM_SET(rip, 0);
    rip->src.addr  = sta_ip;
    rip->dest.addr = unicast_response ? iphdr->src.addr : MDNS_MCAST_IP4;
    IPH_CHKSUM_SET(rip, inet_chksum(rip, 20));

    uint8_t *rudp = buf + 14 + 20;
    rudp[0] = (uint8_t)(MDNS_PORT >> 8);
    rudp[1] = (uint8_t)(MDNS_PORT & 0xFF);
    /* Multicast reply uses sport=5353; unicast goes back to querier sport. */
    if (unicast_response) {
        rudp[2] = (uint8_t)(sport >> 8);
        rudp[3] = (uint8_t)(sport & 0xFF);
    } else {
        rudp[2] = (uint8_t)(MDNS_PORT >> 8);
        rudp[3] = (uint8_t)(MDNS_PORT & 0xFF);
    }
    rudp[4] = (uint8_t)(udp_total >> 8);
    rudp[5] = (uint8_t)(udp_total & 0xFF);
    rudp[6] = 0; rudp[7] = 0;

    uint8_t *rdns = rudp + 8;
    rdns[0] = 0; rdns[1] = 0;
    rdns[2] = 0x84;                         /* QR=1, AA=1 */
    rdns[3] = 0;
    rdns[4] = 0; rdns[5] = 0;
    rdns[6] = 0; rdns[7] = 1;
    rdns[8] = 0; rdns[9] = 0;
    rdns[10] = 0; rdns[11] = 0;

    uint8_t *ans = rdns + 12;
    size_t ai = 0;
    ans[ai++] = (uint8_t)host_len;
    memcpy(ans + ai, hostname, host_len);
    ai += host_len;
    ans[ai++] = 5;
    static const char local_s[5] = { 'l','o','c','a','l' };
    memcpy(ans + ai, local_s, 5);
    ai += 5;
    ans[ai++] = 0;
    ans[ai++] = 0; ans[ai++] = 1;           /* type A */
    ans[ai++] = 0x80; ans[ai++] = 1;        /* class IN, cache-flush */
    ans[ai++] = 0; ans[ai++] = 0; ans[ai++] = 0; ans[ai++] = 120;
    ans[ai++] = 0; ans[ai++] = 4;
    memcpy(ans + ai, &sta_ip, 4);

    if (ap_netif->linkoutput) {
        ap_netif->linkoutput(ap_netif, resp);
    }
    pbuf_free(resp);
    ESP_LOGD(TAG, "answered AP-side mDNS query for %s.local (%s)",
             hostname, unicast_response ? "unicast" : "multicast");
}

#endif
