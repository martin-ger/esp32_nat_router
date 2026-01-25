/* ACL (Access Control List) Firewall Component
 *
 * Provides packet filtering capabilities for the ESP32 NAT Router.
 *
 * Network topology:
 *   Internet <---> [STA] ESP32 [AP] <---> Internal Clients
 *
 * ACL naming convention (from the router's interface perspective):
 * - to_sta:   Internet -> ESP32 (incoming on STA interface)
 * - from_sta: ESP32 -> Internet (outgoing on STA interface)
 * - to_ap:    Clients -> ESP32 (incoming on AP interface)
 * - from_ap:  ESP32 -> Clients (outgoing on AP interface)
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "lwip/pbuf.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ACL list indices */
#define ACL_TO_STA    0   /* Internet -> ESP32 (STA interface input) */
#define ACL_FROM_STA  1   /* ESP32 -> Internet (STA interface output) */
#define ACL_TO_AP     2   /* Clients -> ESP32 (AP interface input) */
#define ACL_FROM_AP   3   /* ESP32 -> Clients (AP interface output) */
#define MAX_ACL_LISTS 4

/* Maximum rules per ACL list */
#define MAX_ACL_ENTRIES 16

/* ACL action codes */
#define ACL_DENY        0x00  /* Drop packet */
#define ACL_ALLOW       0x01  /* Allow packet */
#define ACL_MONITOR     0x02  /* Flag: also send to PCAP capture */
#define ACL_NO_MATCH    0xFF  /* No rule matched (packet allowed by default) */

/* Protocol constants */
#define ACL_PROTO_IP    0     /* Any IP protocol */
#define ACL_PROTO_ICMP  1     /* ICMP */
#define ACL_PROTO_TCP   6     /* TCP */
#define ACL_PROTO_UDP   17    /* UDP */

/**
 * @brief ACL rule entry structure
 */
typedef struct {
    uint32_t src;        /* Source IP (pre-masked) */
    uint32_t s_mask;     /* Source subnet mask */
    uint32_t dest;       /* Destination IP (pre-masked) */
    uint32_t d_mask;     /* Destination subnet mask */
    uint16_t s_port;     /* Source port (0 = any, TCP/UDP only) */
    uint16_t d_port;     /* Destination port (0 = any, TCP/UDP only) */
    uint8_t proto;       /* Protocol: 0=any, 6=TCP, 17=UDP */
    uint8_t allow;       /* Action: ACL_DENY, ACL_ALLOW, or with ACL_MONITOR */
    uint32_t hit_count;  /* Number of packets matched by this rule */
    uint8_t valid;       /* Entry is valid/active */
} acl_entry_t;

/**
 * @brief ACL statistics structure
 */
typedef struct {
    uint32_t packets_allowed;   /* Packets allowed (explicit rule) */
    uint32_t packets_denied;    /* Packets denied */
    uint32_t packets_nomatch;   /* Packets with no matching rule (allowed by default) */
} acl_stats_t;

/**
 * @brief Initialize the ACL subsystem
 * Clears all ACL lists and statistics.
 */
void acl_init(void);

/**
 * @brief Check if an ACL list is empty (has no rules)
 * @param acl_no ACL list index (0-3)
 * @return true if the list has no rules, false if it has rules
 */
bool acl_is_empty(uint8_t acl_no);

/**
 * @brief Get number of rules in an ACL list
 * @param acl_no ACL list index (0-3)
 * @return Number of valid rules in the list
 */
int acl_get_count(uint8_t acl_no);

/**
 * @brief Clear all rules from an ACL list
 * @param acl_no ACL list index (0-3)
 */
void acl_clear(uint8_t acl_no);

/**
 * @brief Clear statistics for an ACL list
 * @param acl_no ACL list index (0-3)
 */
void acl_clear_stats(uint8_t acl_no);

/**
 * @brief Add a rule to an ACL list
 * @param acl_no ACL list index (0-3)
 * @param src Source IP address (network byte order)
 * @param s_mask Source subnet mask (network byte order)
 * @param dest Destination IP address (network byte order)
 * @param d_mask Destination subnet mask (network byte order)
 * @param proto Protocol (0=any, 6=TCP, 17=UDP)
 * @param s_port Source port (0=any, host byte order)
 * @param d_port Destination port (0=any, host byte order)
 * @param allow Action (ACL_DENY, ACL_ALLOW, optionally OR'd with ACL_MONITOR)
 * @return true on success, false if list is full or invalid parameters
 */
bool acl_add(uint8_t acl_no, uint32_t src, uint32_t s_mask,
             uint32_t dest, uint32_t d_mask, uint8_t proto,
             uint16_t s_port, uint16_t d_port, uint8_t allow);

/**
 * @brief Delete a rule from an ACL list by index
 * @param acl_no ACL list index (0-3)
 * @param rule_idx Rule index within the list (0-15)
 * @return true if rule was deleted, false if invalid index
 */
bool acl_delete(uint8_t acl_no, uint8_t rule_idx);

/**
 * @brief Check a packet against an ACL list
 * @param acl_no ACL list index (0-3)
 * @param p Packet buffer to check
 * @return Action code (ACL_DENY, ACL_ALLOW, ACL_ALLOW|ACL_MONITOR, ACL_DENY|ACL_MONITOR, or ACL_NO_MATCH)
 */
uint8_t acl_check_packet(uint8_t acl_no, struct pbuf *p);

/**
 * @brief Get the ACL rules array for a list (for display/NVS)
 * @param acl_no ACL list index (0-3)
 * @return Pointer to the rules array, or NULL if invalid acl_no
 */
acl_entry_t* acl_get_rules(uint8_t acl_no);

/**
 * @brief Get statistics for an ACL list
 * @param acl_no ACL list index (0-3)
 * @return Pointer to statistics structure, or NULL if invalid acl_no
 */
acl_stats_t* acl_get_stats(uint8_t acl_no);

/**
 * @brief Print ACL list to console (for CLI)
 * @param acl_no ACL list index (0-3)
 */
void acl_print(uint8_t acl_no);

/**
 * @brief Get ACL list name string
 * @param acl_no ACL list index (0-3)
 * @return List name string or "unknown"
 */
const char* acl_get_name(uint8_t acl_no);

/**
 * @brief Get ACL list description
 * @param acl_no ACL list index (0-3)
 * @return List name string or "unknown"
 */
const char* acl_get_desc(uint8_t acl_no);

/**
 * @brief Parse ACL list name to index
 * @param name List name ("from_sta", "to_sta", "from_ap", "to_ap")
 * @return List index (0-3) or -1 if invalid name
 */
int acl_parse_name(const char* name);

/**
 * @brief Format an IP address with optional CIDR notation
 * @param ip IP address (network byte order)
 * @param mask Subnet mask (network byte order)
 * @param buf Output buffer
 * @param buf_len Buffer length
 * @return Pointer to buf
 */
char* acl_format_ip(uint32_t ip, uint32_t mask, char* buf, size_t buf_len);

/**
 * @brief Parse an IP address with optional CIDR notation
 * @param str Input string (e.g., "192.168.1.0/24" or "any")
 * @param ip Output IP address (network byte order)
 * @param mask Output subnet mask (network byte order)
 * @return true on success, false on parse error
 */
bool acl_parse_ip(const char* str, uint32_t* ip, uint32_t* mask);

#ifdef __cplusplus
}
#endif
