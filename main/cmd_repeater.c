#include "sdkconfig.h"

#if CONFIG_REPEATER_MODE

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include "esp_console.h"
#include "esp_log.h"
#include "argtable3/argtable3.h"
#include "fdb.h"
#include "dhcp_xid_map.h"
#include "repeater_config.h"
#include "cmd_repeater.h"

static struct {
    struct arg_str *sub;
    struct arg_end *end;
} s_repeater_args;

static void print_fdb(void) {
    fdb_snapshot_entry_t ents[REPEATER_FDB_SIZE];
    int n = fdb_snapshot(ents, REPEATER_FDB_SIZE);
    printf("FDB (%d entries):\n", n);
    printf("  %-16s  %-17s  %s\n", "IP", "MAC", "TTL(s)");
    for (int i = 0; i < n; i++) {
        uint8_t *ipb = (uint8_t *)&ents[i].ip;
        printf("  %3u.%3u.%3u.%3u  %02x:%02x:%02x:%02x:%02x:%02x  %" PRId32 "\n",
               ipb[0], ipb[1], ipb[2], ipb[3],
               ents[i].mac[0], ents[i].mac[1], ents[i].mac[2],
               ents[i].mac[3], ents[i].mac[4], ents[i].mac[5],
               ents[i].ttl_remaining);
    }
}

static void print_xid(void) {
    dhcp_xid_snapshot_entry_t ents[REPEATER_XID_MAP_SIZE];
    int n = dhcp_xid_map_snapshot(ents, REPEATER_XID_MAP_SIZE);
    printf("DHCP XID map (%d entries):\n", n);
    printf("  %-10s  %-17s  %s\n", "XID", "CHADDR", "TTL(s)");
    for (int i = 0; i < n; i++) {
        printf("  0x%08" PRIx32 "  %02x:%02x:%02x:%02x:%02x:%02x  %" PRId32 "\n",
               ents[i].xid,
               ents[i].chaddr[0], ents[i].chaddr[1], ents[i].chaddr[2],
               ents[i].chaddr[3], ents[i].chaddr[4], ents[i].chaddr[5],
               ents[i].ttl_remaining);
    }
}

static int repeater_cmd(int argc, char **argv) {
    int nerrors = arg_parse(argc, argv, (void **)&s_repeater_args);
    if (nerrors != 0) {
        arg_print_errors(stderr, s_repeater_args.end, argv[0]);
        return 1;
    }
    const char *sub = (s_repeater_args.sub->count > 0) ? s_repeater_args.sub->sval[0] : "show";
    if (strcmp(sub, "show") == 0) {
        printf("Mode: L2 bridge (CONFIG_REPEATER_MODE=y)\n");
        print_fdb();
        print_xid();
    } else if (strcmp(sub, "fdb") == 0) {
        print_fdb();
    } else if (strcmp(sub, "xid") == 0) {
        print_xid();
    } else if (strcmp(sub, "clear") == 0) {
        fdb_clear();
        printf("FDB cleared.\n");
    } else {
        printf("Usage: repeater [show|fdb|xid|clear]\n");
        return 1;
    }
    return 0;
}

void register_repeater_cli(void) {
    s_repeater_args.sub = arg_str0(NULL, NULL, "<show|fdb|xid|clear>",
                                   "Subcommand (default: show)");
    s_repeater_args.end = arg_end(2);
    const esp_console_cmd_t cmd = {
        .command = "repeater",
        .help = "L2 repeater state: show|fdb|xid|clear",
        .hint = NULL,
        .func = &repeater_cmd,
        .argtable = &s_repeater_args,
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&cmd));
}

#endif
