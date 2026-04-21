#pragma once

#include "sdkconfig.h"

#if CONFIG_REPEATER_MODE

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* DHCP BOOTP op codes */
#define DHCP_BOOTP_REQUEST  1
#define DHCP_BOOTP_REPLY    2

/* DHCP option tags we care about */
#define DHCP_OPT_PAD         0
#define DHCP_OPT_MSG_TYPE   53
#define DHCP_OPT_CLIENT_ID  61
#define DHCP_OPT_END       255

/* DHCP message types (Option 53) */
#define DHCPDISCOVER 1
#define DHCPOFFER    2
#define DHCPREQUEST  3
#define DHCPDECLINE  4
#define DHCPACK      5
#define DHCPNAK      6
#define DHCPRELEASE  7
#define DHCPINFORM   8

/* Parsed view of a DHCP packet. Pointers reference the input buffer. */
typedef struct {
    uint8_t  op;            /* BOOTP op */
    uint8_t  htype;
    uint8_t  hlen;
    uint32_t xid;           /* host byte order */
    uint8_t  chaddr[6];     /* first 6 bytes of chaddr (Ethernet) */
    uint8_t  msg_type;      /* DHCP Option 53, 0 if missing */
    bool     has_client_id; /* Option 61 present */
} dhcp_parsed_t;

/* Parse a UDP DHCP payload (server port 67 or client port 68).
 * Returns true on success, populating out.
 * The buffer must start at the BOOTP header (not UDP/IP). */
bool dhcp_parse(const uint8_t *buf, size_t len, dhcp_parsed_t *out);

/* Locate Option 53 (msg type). Returns 0 if not present. */
uint8_t dhcp_get_msg_type(const uint8_t *buf, size_t len);

/* Check whether Option 61 (Client Identifier) is present. */
bool dhcp_has_client_id(const uint8_t *buf, size_t len);

#endif
