#include "dhcp_helpers.h"

#if CONFIG_REPEATER_MODE

#include <string.h>
#include "lwip/pbuf.h"
#include "lwip/prot/ip4.h"
#include "lwip/inet_chksum.h"
#include "dhcp_xid_map.h"

/* BOOTP header layout:
 *   0  op(1) htype(1) hlen(1) hops(1)
 *   4  xid(4)
 *   8  secs(2) flags(2)
 *  12  ciaddr(4)
 *  16  yiaddr(4)
 *  20  siaddr(4)
 *  24  giaddr(4)
 *  28  chaddr(16)
 *  44  sname(64)
 * 108  file(128)
 * 236  magic cookie(4) = 0x63825363
 * 240  options...
 */
#define DHCP_MIN_LEN       240
#define DHCP_MAGIC_OFFSET  236
#define DHCP_OPTS_OFFSET   240
#define DHCP_MAGIC_COOKIE  0x63825363u

static bool find_option(const uint8_t *buf, size_t len, uint8_t tag,
                        const uint8_t **val_out, uint8_t *vlen_out) {
    if (len < DHCP_OPTS_OFFSET) return false;
    size_t i = DHCP_OPTS_OFFSET;
    while (i < len) {
        uint8_t t = buf[i++];
        if (t == DHCP_OPT_END) return false;
        if (t == DHCP_OPT_PAD) continue;
        if (i >= len) return false;
        uint8_t l = buf[i++];
        if (i + l > len) return false;
        if (t == tag) {
            if (val_out) *val_out = &buf[i];
            if (vlen_out) *vlen_out = l;
            return true;
        }
        i += l;
    }
    return false;
}

bool dhcp_parse(const uint8_t *buf, size_t len, dhcp_parsed_t *out) {
    if (!buf || !out || len < DHCP_MIN_LEN) return false;
    uint32_t magic = ((uint32_t)buf[DHCP_MAGIC_OFFSET] << 24) |
                     ((uint32_t)buf[DHCP_MAGIC_OFFSET+1] << 16) |
                     ((uint32_t)buf[DHCP_MAGIC_OFFSET+2] << 8)  |
                      (uint32_t)buf[DHCP_MAGIC_OFFSET+3];
    if (magic != DHCP_MAGIC_COOKIE) return false;

    memset(out, 0, sizeof(*out));
    out->op    = buf[0];
    out->htype = buf[1];
    out->hlen  = buf[2];
    out->xid = ((uint32_t)buf[4] << 24) | ((uint32_t)buf[5] << 16) |
               ((uint32_t)buf[6] << 8)  |  (uint32_t)buf[7];
    memcpy(out->chaddr, &buf[28], 6);
    memcpy(&out->yiaddr, &buf[16], 4);

    const uint8_t *v = NULL;
    uint8_t vl = 0;
    if (find_option(buf, len, DHCP_OPT_MSG_TYPE, &v, &vl) && vl >= 1) {
        out->msg_type = v[0];
    }
    out->has_client_id = find_option(buf, len, DHCP_OPT_CLIENT_ID, NULL, NULL);
    if (find_option(buf, len, DHCP_OPT_LEASE_TIME, &v, &vl) && vl >= 4) {
        out->lease_time = ((uint32_t)v[0] << 24) | ((uint32_t)v[1] << 16) |
                          ((uint32_t)v[2] << 8)  |  (uint32_t)v[3];
    }
    if (find_option(buf, len, DHCP_OPT_HOSTNAME, &v, &vl) && vl > 0) {
        uint8_t clen = vl < DHCP_HOSTNAME_MAX - 1 ? vl : DHCP_HOSTNAME_MAX - 1;
        memcpy(out->hostname, v, clen);
        out->hostname[clen] = '\0';
    }
    return true;
}

uint8_t dhcp_get_msg_type(const uint8_t *buf, size_t len) {
    const uint8_t *v = NULL; uint8_t vl = 0;
    if (find_option(buf, len, DHCP_OPT_MSG_TYPE, &v, &vl) && vl >= 1) return v[0];
    return 0;
}

bool dhcp_has_client_id(const uint8_t *buf, size_t len) {
    return find_option(buf, len, DHCP_OPT_CLIENT_ID, NULL, NULL);
}

/* ---- Egress / ingress mangling for the DHCP relay-ish bridge path ---- */

/* Locate the DHCP payload offset within an Ethernet frame (offset from start
 * of the Ethernet header). Returns 0 on failure. Also returns the IP header
 * length and UDP payload length via out params. */
static size_t locate_dhcp_in_frame(const uint8_t *eth, size_t frame_len,
                                   uint16_t want_sport, uint16_t want_dport,
                                   uint8_t *ihl_out, size_t *dhcp_len_out) {
    if (frame_len < 14 + 20 + 8 + DHCP_MIN_LEN) return 0;
    if (eth[12] != 0x08 || eth[13] != 0x00) return 0;
    const struct ip_hdr *iphdr = (const struct ip_hdr *)(eth + 14);
    if (IPH_V(iphdr) != 4) return 0;
    uint8_t ihl = IPH_HL(iphdr) * 4;
    if (ihl < 20 || frame_len < 14u + ihl + 8 + DHCP_MIN_LEN) return 0;
    if (IPH_PROTO(iphdr) != 17) return 0;
    const uint8_t *udp = eth + 14 + ihl;
    uint16_t sport = ((uint16_t)udp[0] << 8) | udp[1];
    uint16_t dport = ((uint16_t)udp[2] << 8) | udp[3];
    if (sport != want_sport || dport != want_dport) return 0;
    if (ihl_out) *ihl_out = ihl;
    if (dhcp_len_out) *dhcp_len_out = frame_len - 14 - ihl - 8;
    return 14 + ihl + 8;
}

/* Find Option END index inside DHCP options region. Returns offset (from
 * start of dhcp buffer) of the END byte, or 0 if not found. */
static size_t find_options_end(const uint8_t *dhcp, size_t dlen) {
    if (dlen < DHCP_OPTS_OFFSET) return 0;
    size_t i = DHCP_OPTS_OFFSET;
    while (i < dlen) {
        uint8_t t = dhcp[i];
        if (t == DHCP_OPT_END) return i;
        if (t == DHCP_OPT_PAD) { i++; continue; }
        if (i + 1 >= dlen) return 0;
        uint8_t l = dhcp[i + 1];
        if (i + 2 + l > dlen) return 0;
        i += 2 + l;
    }
    return 0;
}

struct pbuf *dhcp_mangle_request_egress(struct pbuf *p,
                                        const uint8_t real_mac[6],
                                        const uint8_t sta_mac[6]) {
    if (!p || p->len < 14 + 20 + 8 + DHCP_MIN_LEN) return p;

    uint8_t *eth = (uint8_t *)p->payload;
    uint8_t ihl = 0;
    size_t dlen = 0;
    size_t dhcp_off = locate_dhcp_in_frame(eth, p->len, 68, 67, &ihl, &dlen);
    if (!dhcp_off) return p;

    uint8_t *dhcp = eth + dhcp_off;

    /* In-place mutations: chaddr → STA MAC, broadcast flag, zero UDP cksum. */
    memcpy(dhcp + 28, sta_mac, 6);
    dhcp[10] |= 0x80;            /* flags high byte = broadcast bit */
    uint8_t *udp = eth + 14 + ihl;
    udp[6] = 0; udp[7] = 0;       /* zero UDP checksum (legal for IPv4) */

    /* Append option 61 if missing (and we have a real MAC). */
    bool need_opt61 = !find_option(dhcp, dlen, DHCP_OPT_CLIENT_ID, NULL, NULL);
    if (need_opt61) {
        size_t end_off = find_options_end(dhcp, dlen);
        if (end_off == 0) goto patch_lengths;     /* malformed, skip */
        const size_t add = 9;                      /* tag(1)+len(1)+type(1)+mac(6) */
        size_t new_frame_len = p->len + add;

        /* pbuf_realloc only shrinks; for growth we must allocate fresh. */
        struct pbuf *target = pbuf_alloc(PBUF_RAW, new_frame_len, PBUF_RAM);
        if (!target) goto patch_lengths;             /* OOM: skip opt-61 */
        if (pbuf_copy(target, p) != ERR_OK) {
            pbuf_free(target);
            goto patch_lengths;
        }

        uint8_t *teth  = (uint8_t *)target->payload;
        uint8_t *tdhcp = teth + dhcp_off;
        /* Overwrite the old END byte with the new option, then append END. */
        tdhcp[end_off + 0] = DHCP_OPT_CLIENT_ID;
        tdhcp[end_off + 1] = 7;                    /* len: 1 type byte + 6 MAC */
        tdhcp[end_off + 2] = 1;                    /* hardware type: Ethernet */
        memcpy(tdhcp + end_off + 3, real_mac, 6);
        tdhcp[end_off + 9] = DHCP_OPT_END;

        /* Patch IP total length (+9), recompute IP checksum, patch UDP length. */
        struct ip_hdr *tip = (struct ip_hdr *)(teth + 14);
        uint16_t ip_len = lwip_ntohs(IPH_LEN(tip)) + add;
        IPH_LEN_SET(tip, lwip_htons(ip_len));
        IPH_CHKSUM_SET(tip, 0);
        IPH_CHKSUM_SET(tip, inet_chksum(tip, ihl));
        uint8_t *tudp = teth + 14 + ihl;
        uint16_t udp_len = (((uint16_t)tudp[4]) << 8 | tudp[5]) + add;
        tudp[4] = (uint8_t)(udp_len >> 8);
        tudp[5] = (uint8_t)(udp_len & 0xFF);
        tudp[6] = 0; tudp[7] = 0;                  /* keep UDP cksum zero */

        if (target != p) {
            return target;                          /* caller frees p */
        }
        return p;
    }

patch_lengths:
    /* Even without option 61 we already mutated chaddr/flags/UDP cksum — no
     * length change needed, but the IP checksum is unchanged because the IP
     * header was not touched, and the UDP checksum is now zero. */
    return p;
}

bool dhcp_mangle_reply_ingress(struct pbuf *p, uint8_t chaddr_out[6]) {
    if (!p || p->len < 14 + 20 + 8 + DHCP_MIN_LEN) return false;
    uint8_t *eth = (uint8_t *)p->payload;
    uint8_t ihl = 0;
    size_t dlen = 0;
    size_t dhcp_off = locate_dhcp_in_frame(eth, p->len, 67, 68, &ihl, &dlen);
    if (!dhcp_off) return false;

    uint8_t *dhcp = eth + dhcp_off;
    uint32_t xid = ((uint32_t)dhcp[4] << 24) | ((uint32_t)dhcp[5] << 16) |
                   ((uint32_t)dhcp[6] << 8)  |  (uint32_t)dhcp[7];
    uint8_t real_mac[6];
    if (!dhcp_xid_map_lookup(xid, real_mac)) return false;

    memcpy(dhcp + 28, real_mac, 6);
    /* Zero UDP checksum since we mutated payload (and it's optional for v4). */
    uint8_t *udp = eth + 14 + ihl;
    udp[6] = 0; udp[7] = 0;

    if (chaddr_out) memcpy(chaddr_out, real_mac, 6);
    return true;
}

#endif
