/* Network interface hooks: byte counting, ACL enforcement, PCAP capture,
 * TTL override, TCP MSS clamping, Path MTU, and VPN kill switch.
 *
 * Hooks into the lwIP netif input/linkoutput chains for both STA/ETH
 * and AP interfaces to intercept packets for filtering and monitoring.
 */

#include <inttypes.h>
#include <string.h>
#include <time.h>
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "driver/gpio.h"
#include "lwip/netif.h"
#include "lwip/ip_addr.h"
#include "lwip/pbuf.h"
#include "lwip/prot/ip4.h"
#include "lwip/inet_chksum.h"
#include "acl.h"
#include "client_stats.h"
#include "pcap_capture.h"
#include "router_config.h"
#include "wifi_config.h"
#include "vpn_config.h"
#include "led_strip_status.h"

#if CONFIG_ETH_UPLINK
#include "esp_eth.h"
extern esp_netif_t* ethNetif;
#else
extern esp_netif_t* wifiSTA;
#endif
extern esp_netif_t* wifiAP;

static const char *TAG = "netif_hooks";

// Original netif input and linkoutput function pointers
static netif_input_fn original_netif_input = NULL;
static netif_linkoutput_fn original_netif_linkoutput = NULL;
static struct netif *sta_netif = NULL;

// Original AP netif function pointers
static netif_input_fn original_ap_netif_input = NULL;
static netif_linkoutput_fn original_ap_netif_linkoutput = NULL;
static struct netif *ap_netif = NULL;

// Per-client traffic statistics for AP clients
static client_stats_entry_t client_stats[CLIENT_STATS_MAX];

static inline client_stats_entry_t* find_client_stats(const uint8_t *mac) {
    for (int i = 0; i < CLIENT_STATS_MAX; i++) {
        if (client_stats[i].active && memcmp(client_stats[i].mac, mac, 6) == 0) {
            return &client_stats[i];
        }
    }
    return NULL;
}

void client_stats_on_connect(const uint8_t *mac) {
    // Keep existing stats on reconnect
    client_stats_entry_t *existing = find_client_stats(mac);
    if (existing) {
        existing->connected = 1;
        return;
    }
    // Find free slot: prefer inactive, then disconnected
    int free_slot = -1;
    int disconnected_slot = -1;
    for (int i = 0; i < CLIENT_STATS_MAX; i++) {
        if (!client_stats[i].active) {
            free_slot = i;
            break;
        } else if (!client_stats[i].connected && disconnected_slot < 0) {
            disconnected_slot = i;
        }
    }
    int slot = (free_slot >= 0) ? free_slot : disconnected_slot;
    if (slot >= 0) {
        memcpy(client_stats[slot].mac, mac, 6);
        client_stats[slot].bytes_sent = 0;
        client_stats[slot].bytes_received = 0;
        client_stats[slot].packets_sent = 0;
        client_stats[slot].packets_received = 0;
        client_stats[slot].active = 1;
        client_stats[slot].connected = 1;
    }
}

void client_stats_on_disconnect(const uint8_t *mac) {
    client_stats_entry_t *entry = find_client_stats(mac);
    if (entry) {
        entry->connected = 0;
    }
}

int client_stats_get_all(client_stats_entry_t *out, int max_entries) {
    int count = 0;
    for (int i = 0; i < CLIENT_STATS_MAX && count < max_entries; i++) {
        if (client_stats[i].active) {
            memcpy(&out[count], &client_stats[i], sizeof(client_stats_entry_t));
            count++;
        }
    }
    return count;
}

void client_stats_reset_all(void) {
    for (int i = 0; i < CLIENT_STATS_MAX; i++) {
        if (client_stats[i].active) {
            client_stats[i].bytes_sent = 0;
            client_stats[i].bytes_received = 0;
            client_stats[i].packets_sent = 0;
            client_stats[i].packets_received = 0;
        }
    }
}

void format_bytes_human(uint64_t bytes, char *buf, size_t len) {
    if (bytes >= 1073741824ULL)
        snprintf(buf, len, "%.1f GB", (double)bytes / 1073741824.0);
    else if (bytes >= 1048576ULL)
        snprintf(buf, len, "%.1f MB", (double)bytes / 1048576.0);
    else if (bytes >= 1024ULL)
        snprintf(buf, len, "%.1f KB", (double)bytes / 1024.0);
    else
        snprintf(buf, len, "%" PRIu64 " B", bytes);
}

// Hook function to count received bytes via netif input and ACL check
static err_t netif_input_hook(struct pbuf *p, struct netif *netif) {
    bool is_acl_monitored = false;

    // Check to_esp ACL (packets from Internet to ESP32)
    if (!acl_is_empty(ACL_TO_ESP)) {
        uint8_t result = acl_check_packet(ACL_TO_ESP, p);

        // Check if packet has monitor flag
        is_acl_monitored = (result != ACL_NO_MATCH) && (result & ACL_MONITOR) != 0;

        // Handle deny action (logging done in acl_check_packet)
        if ((result & 0x01) == ACL_DENY && result != ACL_NO_MATCH) {
            // Capture denied packet if monitoring is enabled before dropping
            if (is_acl_monitored && pcap_should_capture(true, false)) {
                pcap_capture_packet(p);
            }
            pbuf_free(p);
            return ERR_OK;
        }
    }

    // Capture packet based on mode and ACL monitor flag (STA interface = false)
    if (pcap_should_capture(is_acl_monitored, false)) {
        pcap_capture_packet(p);
    }

    // Count received bytes and toggle LED
    if (netif == sta_netif && p != NULL) {
        sta_bytes_received += p->tot_len;
        if (led_gpio >= 0 && ap_connect) {
            led_toggle ^= 1;
            gpio_set_level(led_gpio, led_toggle ^ led_lowactive);
        }
        if (led_strip_gpio >= 0) {
            led_strip_notify_traffic();
        }
    }

    // Call original input function
    if (original_netif_input != NULL) {
        return original_netif_input(p, netif);
    }

    return ERR_VAL;
}


// Hook function to count sent bytes via netif linkoutput and ACL check
static err_t netif_linkoutput_hook(struct netif *netif, struct pbuf *p) {
    bool is_acl_monitored = false;

    // Check from_esp ACL (packets from ESP32 to Internet)
    if (!acl_is_empty(ACL_FROM_ESP)) {
        uint8_t result = acl_check_packet(ACL_FROM_ESP, p);

        // Check if packet has monitor flag
        is_acl_monitored = (result != ACL_NO_MATCH) && (result & ACL_MONITOR) != 0;

        // Handle deny action (logging done in acl_check_packet)
        if ((result & 0x01) == ACL_DENY && result != ACL_NO_MATCH) {
            // Capture denied packet if monitoring is enabled before dropping
            if (is_acl_monitored && pcap_should_capture(true, false)) {
                pcap_capture_packet(p);
            }
            return ERR_OK;
        }
    }

    // TTL override for upstream packets (must be before PCAP capture)
    // Ethernet header: 14 bytes (6 dst + 6 src + 2 ethertype)
    // Use p->len (first segment) to ensure header is accessible in this pbuf
    if (sta_ttl_override > 0 && p != NULL && p->len >= 14 + sizeof(struct ip_hdr)) {
        uint8_t *payload = (uint8_t *)p->payload;
        // Check ethertype for IPv4 (0x0800)
        if (payload[12] == 0x08 && payload[13] == 0x00) {
            struct ip_hdr *iphdr = (struct ip_hdr *)(payload + 14);
            // Verify it's IPv4
            if (IPH_V(iphdr) == 4) {
                // Read 16-bit word containing TTL and protocol
                uint16_t old_ttl_proto = *(uint16_t *)&iphdr->_ttl;
                iphdr->_ttl = sta_ttl_override;
                uint16_t new_ttl_proto = *(uint16_t *)&iphdr->_ttl;

                // RFC 1624: Incremental checksum update
                // HC' = ~(~HC + ~m + m')
                // where HC = old checksum, m = old value, m' = new value
                uint32_t sum = (uint16_t)~iphdr->_chksum;
                sum += (uint16_t)~old_ttl_proto;
                sum += new_ttl_proto;
                // Fold 32-bit sum to 16 bits
                while (sum >> 16) {
                    sum = (sum & 0xFFFF) + (sum >> 16);
                }
                iphdr->_chksum = (uint16_t)~sum;
            }
        }
    }

    // Capture packet based on mode and ACL monitor flag (STA interface = false)
    if (pcap_should_capture(is_acl_monitored, false)) {
        pcap_capture_packet(p);
    }

    // Count sent bytes and toggle LED
    if (netif == sta_netif && p != NULL) {
        sta_bytes_sent += p->tot_len;
        if (led_gpio >= 0 && ap_connect) {
            led_toggle ^= 1;
            gpio_set_level(led_gpio, led_toggle ^ led_lowactive);
        }
        if (led_strip_gpio >= 0) {
            led_strip_notify_traffic();
        }
    }

    // Call original linkoutput function
    if (original_netif_linkoutput != NULL) {
        return original_netif_linkoutput(netif, p);
    }

    return ERR_IF;
}

void init_byte_counter(void) {
#if CONFIG_ETH_UPLINK
    if (ethNetif != NULL && original_netif_input == NULL) {
        extern struct netif *esp_netif_get_netif_impl(esp_netif_t *esp_netif);
        sta_netif = esp_netif_get_netif_impl(ethNetif);
        if (sta_netif != NULL) {
            original_netif_input = sta_netif->input;
            sta_netif->input = netif_input_hook;
            original_netif_linkoutput = sta_netif->linkoutput;
            sta_netif->linkoutput = netif_linkoutput_hook;
            ESP_LOGI(TAG, "Byte counter initialized for ETH interface (input & output)");
        }
    }
#else
    if (wifiSTA != NULL && original_netif_input == NULL) {
        // Get the underlying lwIP netif structure
        esp_netif_t *sta_netif_handle = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
        if (sta_netif_handle != NULL) {
            // Access internal lwIP netif - this is internal API but necessary for hooking
            extern struct netif *esp_netif_get_netif_impl(esp_netif_t *esp_netif);
            sta_netif = esp_netif_get_netif_impl(sta_netif_handle);

            if (sta_netif != NULL) {
                // Store and hook input function
                original_netif_input = sta_netif->input;
                sta_netif->input = netif_input_hook;

                // Store and hook linkoutput function
                original_netif_linkoutput = sta_netif->linkoutput;
                sta_netif->linkoutput = netif_linkoutput_hook;

                ESP_LOGI(TAG, "Byte counter initialized for STA interface (input & output)");
            }
        }
    }
#endif
}

uint64_t get_sta_bytes_sent(void) {
    return sta_bytes_sent;
}

uint64_t get_sta_bytes_received(void) {
    return sta_bytes_received;
}

void reset_sta_byte_counts(void) {
    sta_bytes_sent = 0;
    sta_bytes_received = 0;
}

void resync_connect_count(void) {
    wifi_sta_list_t sta_list;
    if (esp_wifi_ap_get_sta_list(&sta_list) == ESP_OK) {
        connect_count = sta_list.num;
    }
}

// Uptime functions
uint32_t get_uptime_seconds(void) {
    return (uint32_t)(esp_timer_get_time() / 1000000ULL);
}

void format_uptime(uint32_t seconds, char *buf, size_t buf_len) {
    uint32_t days = seconds / 86400;
    uint32_t hours = (seconds % 86400) / 3600;
    uint32_t mins = (seconds % 3600) / 60;
    uint32_t secs = seconds % 60;

    if (days > 0) {
        snprintf(buf, buf_len, "%lud %02lu:%02lu:%02lu",
                 (unsigned long)days, (unsigned long)hours,
                 (unsigned long)mins, (unsigned long)secs);
    } else {
        snprintf(buf, buf_len, "%02lu:%02lu:%02lu",
                 (unsigned long)hours, (unsigned long)mins, (unsigned long)secs);
    }
}

void format_boot_time(char *buf, size_t buf_len) {
    time_t now;
    time(&now);
    if (now < 100000) {
        // Time not yet synchronized
        snprintf(buf, buf_len, "unknown");
        return;
    }
    time_t boot_time = now - (time_t)get_uptime_seconds();
    struct tm timeinfo;
    localtime_r(&boot_time, &timeinfo);
    snprintf(buf, buf_len, "%04d-%02d-%02d %02d:%02d:%02d",
             timeinfo.tm_year + 1900, timeinfo.tm_mon + 1, timeinfo.tm_mday,
             timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);
}

// Clamp the TCP MSS option in a SYN packet to max_mss.
// Operates on raw Ethernet frames (14-byte header + IPv4 + TCP).
// Updates the TCP checksum incrementally (RFC 1624).
static void clamp_tcp_mss(struct pbuf *p, uint16_t max_mss) {
    if (max_mss == 0 || p == NULL) return;
    // Need at least Ethernet(14) + min IP(20) + min TCP(20) in the first segment
    if (p->len < 14 + 20 + 20) return;

    uint8_t *payload = (uint8_t *)p->payload;

    // IPv4 only (ethertype 0x0800)
    if (payload[12] != 0x08 || payload[13] != 0x00) return;

    struct ip_hdr *iphdr = (struct ip_hdr *)(payload + 14);
    if (IPH_V(iphdr) != 4 || IPH_PROTO(iphdr) != PROTO_TCP) return;

    uint16_t ip_hdr_len = IPH_HL(iphdr) * 4;
    if (p->len < 14 + ip_hdr_len + 20) return;

    uint8_t *tcphdr = payload + 14 + ip_hdr_len;

    // SYN flag must be set (TCP flags byte is at offset 13, SYN = bit 1)
    if (!(tcphdr[13] & 0x02)) return;

    uint8_t tcp_hdr_len = (tcphdr[12] >> 4) * 4;
    if (tcp_hdr_len < 20 || p->len < 14 + ip_hdr_len + tcp_hdr_len) return;

    // Scan TCP options for MSS option (kind=2, len=4)
    uint8_t *opt = tcphdr + 20;
    uint8_t *opt_end = tcphdr + tcp_hdr_len;
    while (opt < opt_end) {
        uint8_t kind = opt[0];
        if (kind == 0) break;               // End of option list
        if (kind == 1) { opt++; continue; } // NOP
        if (opt + 1 >= opt_end) break;
        uint8_t opt_len = opt[1];
        if (opt_len < 2 || opt + opt_len > opt_end) break;

        if (kind == 2 && opt_len == 4) {
            uint16_t *mss_ptr = (uint16_t *)(opt + 2);
            if (ntohs(*mss_ptr) > max_mss) {
                uint16_t old_mss_net = *mss_ptr;
                *mss_ptr = htons(max_mss);
                // Incremental TCP checksum update (RFC 1624): HC' = ~(~HC + ~m + m')
                uint16_t *chksum = (uint16_t *)(tcphdr + 16);
                uint32_t sum = (uint16_t)~(*chksum);
                sum += (uint16_t)~old_mss_net;
                sum += htons(max_mss);
                while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
                *chksum = (uint16_t)~sum;
            }
            break;
        }
        opt += opt_len;
    }
}

// Send ICMP Fragmentation Needed (Type 3, Code 4) back to a client on the AP interface.
// 'p' is an inbound Ethernet frame from the AP; 'mtu' is the next-hop MTU to report.
// Only sent when the IP DF flag is set and the IP total length exceeds 'mtu'.
static void send_icmp_frag_needed(struct pbuf *p, struct netif *netif, uint16_t mtu)
{
    if (p == NULL || netif == NULL || original_ap_netif_linkoutput == NULL) return;
    if (p->len < 14 + 20) return; // need Ethernet header + IP header in first segment

    uint8_t *eth = (uint8_t *)p->payload;

    // IPv4 only (ethertype 0x0800)
    if (eth[12] != 0x08 || eth[13] != 0x00) return;

    struct ip_hdr *orig_ip = (struct ip_hdr *)(eth + 14);
    if (IPH_V(orig_ip) != 4) return;

    // Only when the packet exceeds the reported path MTU
    uint16_t ip_total_len = lwip_ntohs(IPH_LEN(orig_ip));
    if (ip_total_len <= mtu) return;

    // Only send ICMP when DF is set and this is not a non-first fragment
    // (DF=1 with offset>0 is malformed; fragments with offset>0 have no full transport header)
    uint16_t flags_offset = lwip_ntohs(IPH_OFFSET(orig_ip));
    if (!(flags_offset & IP_DF)) return;        // DF not set
    if (flags_offset & IP_OFFMASK) return;      // fragment offset > 0

    // Don't generate ICMP errors in response to ICMP (avoid feedback loops)
    if (IPH_PROTO(orig_ip) == 1 /* ICMP */) return;

    uint16_t orig_ihl = IPH_HL(orig_ip) * 4;
    if (orig_ihl < 20 || orig_ihl > 60) return;

    // ICMP body: 2 bytes unused + 2 bytes next-hop MTU + orig IP header + first 8 data bytes
    uint16_t avail_data = (p->len > 14u + orig_ihl) ? (p->len - 14 - orig_ihl) : 0;
    if (avail_data > 8) avail_data = 8;

    uint16_t icmp_body    = 4 + orig_ihl + avail_data; // unused+mtu + orig_hdr + orig_data
    uint16_t icmp_total   = 4 + icmp_body;              // type+code+chksum + body
    uint16_t new_ip_len   = 20 + icmp_total;
    uint16_t frame_len    = 14 + new_ip_len;

    struct pbuf *resp = pbuf_alloc(PBUF_RAW, frame_len, PBUF_RAM);
    if (resp == NULL) return;

    uint8_t *buf = (uint8_t *)resp->payload;
    memset(buf, 0, frame_len);

    // Ethernet: swap src/dst MAC (AP MAC -> client MAC)
    memcpy(buf + 0, eth + 6, 6); // dst = original sender's MAC
    memcpy(buf + 6, eth + 0, 6); // src = our AP MAC (original frame's dst)
    buf[12] = 0x08;
    buf[13] = 0x00;

    // IP header
    struct ip_hdr *rip = (struct ip_hdr *)(buf + 14);
    IPH_VHL_SET(rip, 4, 5);
    IPH_TOS_SET(rip, 0);
    IPH_LEN_SET(rip, lwip_htons(new_ip_len));
    IPH_ID_SET(rip, 0);
    IPH_OFFSET_SET(rip, 0);
    IPH_TTL_SET(rip, 64);
    IPH_PROTO_SET(rip, 1 /* ICMP */);
    IPH_CHKSUM_SET(rip, 0);
    rip->src.addr  = my_ap_ip;
    rip->dest.addr = orig_ip->src.addr;
    IPH_CHKSUM_SET(rip, inet_chksum(rip, 20));

    // ICMP Fragmentation Needed (RFC 1191)
    uint8_t *icmp = buf + 14 + 20;
    icmp[0] = 3;                        // Type: Destination Unreachable
    icmp[1] = 4;                        // Code: Fragmentation Needed, DF set
    icmp[2] = 0; icmp[3] = 0;          // checksum (computed below)
    icmp[4] = 0; icmp[5] = 0;          // unused
    icmp[6] = (uint8_t)(mtu >> 8);     // next-hop MTU high byte
    icmp[7] = (uint8_t)(mtu & 0xFF);   // next-hop MTU low byte
    memcpy(icmp + 8, orig_ip, orig_ihl);
    if (avail_data > 0) {
        memcpy(icmp + 8 + orig_ihl, (uint8_t *)orig_ip + orig_ihl, avail_data);
    }
    *((uint16_t *)(icmp + 2)) = inet_chksum(icmp, icmp_total);

    original_ap_netif_linkoutput(netif, resp);
    pbuf_free(resp);
}

// AP netif hook functions (for PCAP capture and ACL)
static err_t ap_netif_input_hook(struct pbuf *p, struct netif *netif) {
    bool is_acl_monitored = false;

    // Check to_ap ACL (packets from Clients to ESP32)
    if (!acl_is_empty(ACL_TO_AP)) {
        uint8_t result = acl_check_packet(ACL_TO_AP, p);

        // Check if packet has monitor flag
        is_acl_monitored = (result != ACL_NO_MATCH) && (result & ACL_MONITOR) != 0;

        // Handle deny action (logging done in acl_check_packet)
        if ((result & 0x01) == ACL_DENY && result != ACL_NO_MATCH) {
            // Capture denied packet if monitoring is enabled before dropping
            if (is_acl_monitored && pcap_should_capture(true, true)) {
                pcap_capture_packet(p);
            }
            pbuf_free(p);
            return ERR_OK;
        }
    }

    // VPN kill switch: block traffic when VPN is enabled but not connected
    // Route-all mode: block all non-AP-subnet traffic (prevents internet leakage)
    // Split tunnel mode: block only VPN-subnet traffic (internet goes direct via STA)
    if (vpn_enabled && vpn_killswitch && !vpn_is_connected()) {
        if (p != NULL && p->len >= 14 + sizeof(struct ip_hdr)) {
            uint8_t *payload = (uint8_t *)p->payload;
            if (payload[12] == 0x08 && payload[13] == 0x00) {  // IPv4
                struct ip_hdr *iphdr = (struct ip_hdr *)(payload + 14);
                if (IPH_V(iphdr) == 4) {
                    uint32_t dest = iphdr->dest.addr;
                    uint32_t ap_subnet = my_ap_ip & htonl(0xFFFFFF00);
                    bool is_local = (dest & htonl(0xFFFFFF00)) == ap_subnet;
                    if (!is_local) {
                        if (vpn_route_all) {
                            // Block all non-local traffic
                            pbuf_free(p);
                            return ERR_OK;
                        } else if (vpn_in_subnet(dest)) {
                            // Split tunnel: block only VPN-subnet traffic
                            pbuf_free(p);
                            return ERR_OK;
                        }
                    }
                }
            }
        }
    }

    // PMTU: send ICMP Fragmentation Needed if client sends a DF packet larger than path MTU
    if (ap_pmtu > 0) {
        send_icmp_frag_needed(p, netif, ap_pmtu);
    }

    // Clamp TCP MSS on SYN packets from clients
    clamp_tcp_mss(p, ap_mss_clamp);

    // Per-client byte counting: source MAC = client
    if (p != NULL && p->len >= 14) {
        const uint8_t *src_mac = ((const uint8_t *)p->payload) + 6;
        client_stats_entry_t *entry = find_client_stats(src_mac);
        if (entry) {
            entry->bytes_received += p->tot_len;
            entry->packets_received++;
        }
    }

    // Capture packet based on mode and ACL monitor flag (AP interface = true)
    if (pcap_should_capture(is_acl_monitored, true)) {
        pcap_capture_packet(p);
    }

    // Call original input function
    if (original_ap_netif_input != NULL) {
        return original_ap_netif_input(p, netif);
    }

    return ERR_VAL;
}

static err_t ap_netif_linkoutput_hook(struct netif *netif, struct pbuf *p) {
    bool is_acl_monitored = false;

    // Check from_ap ACL (packets from ESP32 to Clients)
    if (!acl_is_empty(ACL_FROM_AP)) {
        uint8_t result = acl_check_packet(ACL_FROM_AP, p);

        // Check if packet has monitor flag
        is_acl_monitored = (result != ACL_NO_MATCH) && (result & ACL_MONITOR) != 0;

        // Handle deny action (logging done in acl_check_packet)
        if ((result & 0x01) == ACL_DENY && result != ACL_NO_MATCH) {
            // Capture denied packet if monitoring is enabled before dropping
            if (is_acl_monitored && pcap_should_capture(true, true)) {
                pcap_capture_packet(p);
            }
            return ERR_OK;
        }
    }

    // Clamp TCP MSS on SYN/SYN-ACK packets to clients
    clamp_tcp_mss(p, ap_mss_clamp);

    // Per-client byte counting: dest MAC = client
    if (p != NULL && p->len >= 14) {
        const uint8_t *dst_mac = (const uint8_t *)p->payload;
        client_stats_entry_t *entry = find_client_stats(dst_mac);
        if (entry) {
            entry->bytes_sent += p->tot_len;
            entry->packets_sent++;
        }
    }

    // Capture packet based on mode and ACL monitor flag (AP interface = true)
    if (pcap_should_capture(is_acl_monitored, true)) {
        pcap_capture_packet(p);
    }

    // Call original linkoutput function
    if (original_ap_netif_linkoutput != NULL) {
        return original_ap_netif_linkoutput(netif, p);
    }

    return ERR_IF;
}

void init_ap_netif_hooks(void) {
    if (wifiAP != NULL && original_ap_netif_input == NULL) {
        // Get the underlying lwIP netif structure for AP
        esp_netif_t *ap_netif_handle = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
        if (ap_netif_handle != NULL) {
            // Access internal lwIP netif - this is internal API but necessary for hooking
            extern struct netif *esp_netif_get_netif_impl(esp_netif_t *esp_netif);
            ap_netif = esp_netif_get_netif_impl(ap_netif_handle);

            if (ap_netif != NULL) {
                // Store and hook input function
                original_ap_netif_input = ap_netif->input;
                ap_netif->input = ap_netif_input_hook;

                // Store and hook linkoutput function
                original_ap_netif_linkoutput = ap_netif->linkoutput;
                ap_netif->linkoutput = ap_netif_linkoutput_hook;

                ESP_LOGI(TAG, "AP netif hooks initialized (input & output)");
            }
        }
    }
}
