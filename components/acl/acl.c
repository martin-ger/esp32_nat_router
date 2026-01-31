/* ACL (Access Control List) Firewall Implementation
 *
 * Provides packet filtering based on IP addresses, protocols, and ports.
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "esp_log.h"
#include "esp_netif.h"
#include "lwip/ip4.h"
#include "lwip/ip4_addr.h"
#include "lwip/inet.h"
#include "lwip/pbuf.h"
#include "lwip/prot/ip4.h"
#include "lwip/prot/tcp.h"
#include "lwip/prot/udp.h"

#include "acl.h"
#include "esp_timer.h"

/* Protocol numbers (from IANA) */
#define IPPROTO_ICMP 1
#define IPPROTO_TCP  6
#define IPPROTO_UDP  17

/* Rate limiting for deny logs (microseconds) */
#define ACL_LOG_INTERVAL_US  500000  /* 0.5 seconds */

static const char *TAG = "ACL";

/* Last time we logged a denied packet (per ACL list) */
static int64_t last_deny_log_time[MAX_ACL_LISTS] = {0};

/* ACL list names for display/parsing */
static const char* acl_names[MAX_ACL_LISTS] = {
    "to_sta",    /* 0: Internet -> ESP32 (STA input) */
    "from_sta",  /* 1: ESP32 -> Internet (STA output) */
    "to_ap",     /* 2: Clients -> ESP32 (AP input) */
    "from_ap"    /* 3: ESP32 -> Clients (AP output) */
};

/* ACL list description for display */
static const char* acl_desc[MAX_ACL_LISTS] = {
    "Internet -> ESP (to_sta)",
    "ESP -> Internet (from_sta)",
    "Clients -> ESP (to_ap)",
    "ESP -> Clients (from_ap)"
};

/* ACL rule tables - one array per direction */
static acl_entry_t acl_lists[MAX_ACL_LISTS][MAX_ACL_ENTRIES];

/* ACL statistics per list */
static acl_stats_t acl_stats[MAX_ACL_LISTS];

void acl_init(void)
{
    memset(acl_lists, 0, sizeof(acl_lists));
    memset(acl_stats, 0, sizeof(acl_stats));
    ESP_LOGI(TAG, "ACL subsystem initialized");
}

bool acl_is_empty(uint8_t acl_no)
{
    if (acl_no >= MAX_ACL_LISTS) {
        return true;
    }

    for (int i = 0; i < MAX_ACL_ENTRIES; i++) {
        if (acl_lists[acl_no][i].valid) {
            return false;
        }
    }
    return true;
}

int acl_get_count(uint8_t acl_no)
{
    if (acl_no >= MAX_ACL_LISTS) {
        return 0;
    }

    int count = 0;
    for (int i = 0; i < MAX_ACL_ENTRIES; i++) {
        if (acl_lists[acl_no][i].valid) {
            count++;
        }
    }
    return count;
}

void acl_clear(uint8_t acl_no)
{
    if (acl_no >= MAX_ACL_LISTS) {
        return;
    }

    memset(acl_lists[acl_no], 0, sizeof(acl_lists[acl_no]));
    ESP_LOGI(TAG, "Cleared ACL list %s", acl_names[acl_no]);
}

void acl_clear_stats(uint8_t acl_no)
{
    if (acl_no >= MAX_ACL_LISTS) {
        return;
    }

    memset(&acl_stats[acl_no], 0, sizeof(acl_stats_t));

    /* Also clear hit counts on all rules */
    for (int i = 0; i < MAX_ACL_ENTRIES; i++) {
        acl_lists[acl_no][i].hit_count = 0;
    }
}

bool acl_add(uint8_t acl_no, uint32_t src, uint32_t s_mask,
             uint32_t dest, uint32_t d_mask, uint8_t proto,
             uint16_t s_port, uint16_t d_port, uint8_t allow)
{
    if (acl_no >= MAX_ACL_LISTS) {
        ESP_LOGE(TAG, "Invalid ACL list number: %d", acl_no);
        return false;
    }

    /* Find first empty slot */
    int slot = -1;
    for (int i = 0; i < MAX_ACL_ENTRIES; i++) {
        if (!acl_lists[acl_no][i].valid) {
            slot = i;
            break;
        }
    }

    if (slot < 0) {
        ESP_LOGE(TAG, "ACL list %s is full", acl_names[acl_no]);
        return false;
    }

    /* Store the rule with pre-masked IP addresses */
    acl_entry_t *entry = &acl_lists[acl_no][slot];
    entry->src = src & s_mask;
    entry->s_mask = s_mask;
    entry->dest = dest & d_mask;
    entry->d_mask = d_mask;
    entry->proto = proto;
    entry->s_port = s_port;
    entry->d_port = d_port;
    entry->allow = allow;
    entry->hit_count = 0;
    entry->valid = 1;

    ESP_LOGI(TAG, "Added rule %d to ACL %s", slot, acl_names[acl_no]);
    return true;
}

bool acl_delete(uint8_t acl_no, uint8_t rule_idx)
{
    if (acl_no >= MAX_ACL_LISTS || rule_idx >= MAX_ACL_ENTRIES) {
        return false;
    }

    if (!acl_lists[acl_no][rule_idx].valid) {
        return false;
    }

    /* Clear the entry */
    memset(&acl_lists[acl_no][rule_idx], 0, sizeof(acl_entry_t));

    /* Compact the list by moving remaining entries up */
    for (int i = rule_idx; i < MAX_ACL_ENTRIES - 1; i++) {
        if (acl_lists[acl_no][i + 1].valid) {
            memcpy(&acl_lists[acl_no][i], &acl_lists[acl_no][i + 1], sizeof(acl_entry_t));
            memset(&acl_lists[acl_no][i + 1], 0, sizeof(acl_entry_t));
        } else {
            break;
        }
    }

    ESP_LOGI(TAG, "Deleted rule %d from ACL %s", rule_idx, acl_names[acl_no]);
    return true;
}

/* Ethernet header size */
#define ETH_HEADER_LEN 14
#define ETH_TYPE_IPV4  0x0800
#define ETH_TYPE_ARP   0x0806
#define ETH_TYPE_IPV6  0x86DD

uint8_t acl_check_packet(uint8_t acl_no, struct pbuf *p)
{
    if (acl_no >= MAX_ACL_LISTS || p == NULL) {
        return ACL_NO_MATCH;
    }

    uint8_t *payload = (uint8_t *)p->payload;
    uint16_t payload_len = p->len;
    uint16_t offset = 0;

    /* Check if packet has Ethernet header by examining structure.
     * ESP-IDF WiFi passes full Ethernet frames to netif->input.
     * Ethernet header: 6 bytes dst MAC + 6 bytes src MAC + 2 bytes EtherType */
    if (payload_len >= ETH_HEADER_LEN) {
        uint16_t ethertype = (payload[12] << 8) | payload[13];

        /* Check for common EtherTypes indicating this is an Ethernet frame */
        if (ethertype == ETH_TYPE_IPV4 || ethertype == ETH_TYPE_ARP ||
            ethertype == ETH_TYPE_IPV6 || ethertype < 0x0600) {
            /* This looks like an Ethernet frame */
            if (ethertype != ETH_TYPE_IPV4) {
                /* Non-IPv4 (ARP, IPv6, etc.) - allow to pass through */
                return ACL_NO_MATCH;
            }
            /* Skip Ethernet header to get to IP packet */
            offset = ETH_HEADER_LEN;
        }
    }

    /* Check if remaining payload is large enough for IP header */
    if (payload_len < offset + sizeof(struct ip_hdr)) {
        /* Too short - allow by default */
        return ACL_NO_MATCH;
    }

    /* Extract IP header */
    struct ip_hdr *iphdr = (struct ip_hdr *)(payload + offset);

    /* Verify it's IPv4 */
    if (IPH_V(iphdr) != 4) {
        /* Not IPv4 - allow by default (could be raw IP packet of different version) */
        return ACL_NO_MATCH;
    }

    uint32_t src_ip = iphdr->src.addr;
    uint32_t dest_ip = iphdr->dest.addr;
    uint8_t proto = IPH_PROTO(iphdr);

    /* Extract port information for TCP/UDP */
    uint16_t src_port = 0;
    uint16_t dst_port = 0;

    uint16_t ip_hdr_len = IPH_HL(iphdr) * 4;

    if (proto == IPPROTO_TCP && payload_len >= offset + ip_hdr_len + sizeof(struct tcp_hdr)) {
        struct tcp_hdr *tcphdr = (struct tcp_hdr *)(payload + offset + ip_hdr_len);
        src_port = lwip_ntohs(tcphdr->src);
        dst_port = lwip_ntohs(tcphdr->dest);
    } else if (proto == IPPROTO_UDP && payload_len >= offset + ip_hdr_len + sizeof(struct udp_hdr)) {
        struct udp_hdr *udphdr = (struct udp_hdr *)(payload + offset + ip_hdr_len);
        src_port = lwip_ntohs(udphdr->src);
        dst_port = lwip_ntohs(udphdr->dest);
    }

    /* Check rules in order */
    for (int i = 0; i < MAX_ACL_ENTRIES; i++) {
        acl_entry_t *rule = &acl_lists[acl_no][i];

        if (!rule->valid) {
            continue;
        }

        /* Check protocol */
        if (rule->proto != 0 && rule->proto != proto) {
            continue;
        }

        /* Check source IP */
        if ((src_ip & rule->s_mask) != rule->src) {
            continue;
        }

        /* Check destination IP */
        if ((dest_ip & rule->d_mask) != rule->dest) {
            continue;
        }

        /* Check ports if rule has port filters */
        if (rule->s_port != 0 || rule->d_port != 0) {
            /* Rule has port filters - only match TCP/UDP packets */
            if (proto != IPPROTO_TCP && proto != IPPROTO_UDP) {
                /* Can't match ports on non-TCP/UDP packets (e.g., ICMP) */
                continue;
            }
            if (rule->s_port != 0 && rule->s_port != src_port) {
                continue;
            }
            if (rule->d_port != 0 && rule->d_port != dst_port) {
                continue;
            }
        }

        /* Rule matched! */
        rule->hit_count++;

        uint8_t action = rule->allow & 0x01;  /* Extract base action */
        uint8_t monitor = rule->allow & ACL_MONITOR;  /* Extract monitor flag */

        if (action == ACL_ALLOW) {
            acl_stats[acl_no].packets_allowed++;
        } else {
            acl_stats[acl_no].packets_denied++;

            /* Rate-limited logging for denied packets */
            int64_t now = esp_timer_get_time();
            if (now - last_deny_log_time[acl_no] >= ACL_LOG_INTERVAL_US) {
                last_deny_log_time[acl_no] = now;

                /* Format source and destination for logging */
                char src_str[24], dst_str[24];
                ip4_addr_t saddr, daddr;
                saddr.addr = src_ip;
                daddr.addr = dest_ip;
                snprintf(src_str, sizeof(src_str), IPSTR, IP2STR(&saddr));
                snprintf(dst_str, sizeof(dst_str), IPSTR, IP2STR(&daddr));

                const char *proto_name;
                switch (proto) {
                    case IPPROTO_ICMP: proto_name = "ICMP"; break;
                    case IPPROTO_TCP:  proto_name = "TCP"; break;
                    case IPPROTO_UDP:  proto_name = "UDP"; break;
                    default:           proto_name = "IP"; break;
                }

                if (proto == IPPROTO_TCP || proto == IPPROTO_UDP) {
                    ESP_LOGW(TAG, "DENY [%s] %s %s:%d -> %s:%d (rule %d)",
                             acl_names[acl_no], proto_name,
                             src_str, src_port, dst_str, dst_port, i);
                } else {
                    ESP_LOGW(TAG, "DENY [%s] %s %s -> %s (rule %d)",
                             acl_names[acl_no], proto_name,
                             src_str, dst_str, i);
                }
            }
        }

        return action | monitor;
    }

    /* No rule matched - allow packet (permissive default) */
    acl_stats[acl_no].packets_nomatch++;
    return ACL_NO_MATCH;
}

acl_entry_t* acl_get_rules(uint8_t acl_no)
{
    if (acl_no >= MAX_ACL_LISTS) {
        return NULL;
    }
    return acl_lists[acl_no];
}

acl_stats_t* acl_get_stats(uint8_t acl_no)
{
    if (acl_no >= MAX_ACL_LISTS) {
        return NULL;
    }
    return &acl_stats[acl_no];
}

const char* acl_get_name(uint8_t acl_no)
{
    if (acl_no >= MAX_ACL_LISTS) {
        return "unknown";
    }
    return acl_names[acl_no];
}

const char* acl_get_desc(uint8_t acl_no)
{
    if (acl_no >= MAX_ACL_LISTS) {
        return "unknown";
    }
    return acl_desc[acl_no];
}

int acl_parse_name(const char* name)
{
    if (name == NULL) {
        return -1;
    }

    for (int i = 0; i < MAX_ACL_LISTS; i++) {
        if (strcasecmp(name, acl_names[i]) == 0) {
            return i;
        }
    }
    return -1;
}

/* Count number of 1 bits in a mask (for CIDR notation) */
static int count_bits(uint32_t mask)
{
    /* Convert from network byte order */
    uint32_t m = lwip_ntohl(mask);
    int count = 0;
    while (m) {
        count += m & 1;
        m >>= 1;
    }
    return count;
}

char* acl_format_ip(uint32_t ip, uint32_t mask, char* buf, size_t buf_len)
{
    if (buf == NULL || buf_len == 0) {
        return buf;
    }

    /* Check for "any" (0.0.0.0/0) */
    if (ip == 0 && mask == 0) {
        snprintf(buf, buf_len, "any");
        return buf;
    }

    ip4_addr_t addr;
    addr.addr = ip;

    /* Check if it's a full /32 mask */
    if (mask == 0xFFFFFFFF) {
        snprintf(buf, buf_len, IPSTR, IP2STR(&addr));
    } else {
        int cidr = count_bits(mask);
        snprintf(buf, buf_len, IPSTR "/%d", IP2STR(&addr), cidr);
    }

    return buf;
}

bool acl_parse_ip(const char* str, uint32_t* ip, uint32_t* mask)
{
    if (str == NULL || ip == NULL || mask == NULL) {
        return false;
    }

    /* Handle "any" keyword */
    if (strcasecmp(str, "any") == 0) {
        *ip = 0;
        *mask = 0;
        return true;
    }

    /* Look for CIDR notation */
    char ip_str[32];
    strncpy(ip_str, str, sizeof(ip_str) - 1);
    ip_str[sizeof(ip_str) - 1] = '\0';

    char *slash = strchr(ip_str, '/');
    int cidr = 32;  /* Default to /32 if no mask specified */

    if (slash != NULL) {
        *slash = '\0';
        cidr = atoi(slash + 1);
        if (cidr < 0 || cidr > 32) {
            return false;
        }
    }

    /* Parse IP address */
    ip4_addr_t addr;
    if (!ip4addr_aton(ip_str, &addr)) {
        return false;
    }

    *ip = addr.addr;

    /* Build mask from CIDR */
    if (cidr == 0) {
        *mask = 0;
    } else {
        /* Create mask with 'cidr' high bits set, in network byte order */
        uint32_t m = 0xFFFFFFFF << (32 - cidr);
        *mask = lwip_htonl(m);
    }

    /* Pre-mask the IP address */
    *ip = *ip & *mask;

    return true;
}

void acl_print(uint8_t acl_no)
{
    if (acl_no >= MAX_ACL_LISTS) {
        printf("Invalid ACL list number\n");
        return;
    }

    printf("\nACL: %s\n", acl_names[acl_no]);
    printf("==========\n");

    acl_stats_t *stats = &acl_stats[acl_no];
    printf("Stats: allowed=%lu, denied=%lu, no_match=%lu\n",
           (unsigned long)stats->packets_allowed,
           (unsigned long)stats->packets_denied,
           (unsigned long)stats->packets_nomatch);

    if (acl_is_empty(acl_no)) {
        printf("No rules configured (all packets allowed)\n");
        return;
    }

    printf("\n%3s  %-6s  %-20s  %-20s  %-6s  %-6s  %-8s  %s\n",
           "Idx", "Proto", "Source", "Destination", "SPort", "DPort", "Action", "Hits");
    printf("---  ------  --------------------  --------------------  ------  ------  --------  ----\n");

    for (int i = 0; i < MAX_ACL_ENTRIES; i++) {
        acl_entry_t *rule = &acl_lists[acl_no][i];
        if (!rule->valid) {
            continue;
        }

        /* Format protocol */
        const char *proto_str;
        switch (rule->proto) {
            case 0:  proto_str = "IP"; break;
            case 1:  proto_str = "ICMP"; break;
            case 6:  proto_str = "TCP"; break;
            case 17: proto_str = "UDP"; break;
            default: proto_str = "?"; break;
        }

        /* Format IP addresses */
        char src_str[24], dest_str[24];
        acl_format_ip(rule->src, rule->s_mask, src_str, sizeof(src_str));
        acl_format_ip(rule->dest, rule->d_mask, dest_str, sizeof(dest_str));

        /* Format ports */
        char s_port_str[8], d_port_str[8];
        if (rule->s_port == 0) {
            strcpy(s_port_str, "*");
        } else {
            snprintf(s_port_str, sizeof(s_port_str), "%d", rule->s_port);
        }
        if (rule->d_port == 0) {
            strcpy(d_port_str, "*");
        } else {
            snprintf(d_port_str, sizeof(d_port_str), "%d", rule->d_port);
        }

        /* Format action */
        const char *action_str;
        uint8_t action = rule->allow & 0x01;
        uint8_t monitor = rule->allow & ACL_MONITOR;
        if (action == ACL_ALLOW) {
            action_str = monitor ? "allow+M" : "allow";
        } else {
            action_str = monitor ? "deny+M" : "deny";
        }

        printf("%3d  %-6s  %-20s  %-20s  %-6s  %-6s  %-8s  %lu\n",
               i, proto_str, src_str, dest_str, s_port_str, d_port_str,
               action_str, (unsigned long)rule->hit_count);
    }
}
