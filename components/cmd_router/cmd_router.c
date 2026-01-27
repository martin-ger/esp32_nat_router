/* The CLI commands of the router

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <inttypes.h>
#include <stdint.h>
#include "esp_log.h"
#include "esp_console.h"
#include "esp_system.h"
#include "esp_sleep.h"
#include "spi_flash_mmap.h"
#include "driver/rtc_io.h"
#include "driver/uart.h"
#include "argtable3/argtable3.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "sdkconfig.h"
#include "nvs.h"
#include "esp_wifi.h"

#include "lwip/ip4_addr.h"
#if !IP_NAPT
#error "IP_NAPT must be defined"
#endif
#include "lwip/lwip_napt.h"

#include "router_globals.h"
#include "cmd_router.h"
#include "pcap_capture.h"
#include "acl.h"

#ifdef CONFIG_FREERTOS_USE_STATS_FORMATTING_FUNCTIONS
#define WITH_TASKS_INFO 1
#endif

static const char *TAG = "cmd_router";

static void register_set_sta(void);
static void register_set_sta_static(void);
static void register_set_mac(void);
static void register_set_ap(void);
static void register_set_ap_ip(void);
static void register_show(void);
static void register_portmap(void);
static void register_dhcp_reserve(void);
static void register_set_web_password(void);
static void register_disable_enable(void);
static void register_bytes(void);
static void register_pcap(void);
static void register_set_led_gpio(void);
static void register_acl(void);

/* ACL helper functions (forward declarations) */
static char* acl_format_ip_with_name(uint32_t ip, uint32_t mask, char* buf, size_t buf_len);
static bool acl_parse_ip_or_name(const char* str, uint32_t* ip, uint32_t* mask);
static void acl_print_with_names(uint8_t acl_no);

/* Check if character is a valid hex digit */
static inline int is_hex_digit(char c)
{
    return (c >= '0' && c <= '9') ||
           (c >= 'A' && c <= 'F') ||
           (c >= 'a' && c <= 'f');
}

/* Convert hex digit to value (assumes valid hex digit) */
static inline uint8_t hex_digit_value(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    else
        return toupper((unsigned char)c) - 'A' + 10;
}

void preprocess_string(char* str)
{
    char *p, *q;

    for (p = q = str; *p != 0; p++)
    {
        if (*(p) == '%' && *(p + 1) != 0 && *(p + 2) != 0 &&
            is_hex_digit(*(p + 1)) && is_hex_digit(*(p + 2)))
        {
            // Valid percent-encoded hex sequence
            p++;
            uint8_t a = hex_digit_value(*p) << 4;
            p++;
            a += hex_digit_value(*p);
            *q++ = a;
        }
        else if (*(p) == '+') {
            *q++ = ' ';
        } else {
            *q++ = *p;
        }
    }
    *q = '\0';
}

esp_err_t get_config_param_str(char* name, char** param)
{
    nvs_handle_t nvs;

    esp_err_t err = nvs_open(PARAM_NAMESPACE, NVS_READONLY, &nvs);
    if (err == ESP_OK) {
        size_t len;
        if ( (err = nvs_get_str(nvs, name, NULL, &len)) == ESP_OK) {
            *param = (char *)malloc(len);
            if (*param == NULL) {
                nvs_close(nvs);
                return ESP_ERR_NO_MEM;
            }
            err = nvs_get_str(nvs, name, *param, &len);
            ESP_LOGI(TAG, "%s %s", name, *param);
        } else {
            return err;
        }
        nvs_close(nvs);
    } else {
        return err;
    }
    return ESP_OK;
}

esp_err_t get_config_param_int(char* name, int* param)
{
    nvs_handle_t nvs;

    esp_err_t err = nvs_open(PARAM_NAMESPACE, NVS_READONLY, &nvs);
    if (err == ESP_OK) {
        if ( (err = nvs_get_i32(nvs, name, (int32_t*)(param))) == ESP_OK) {
            ESP_LOGI(TAG, "%s %d", name, *param);
        } else {
            return err;
        }
        nvs_close(nvs);
    } else {
        return err;
    }
    return ESP_OK;
}

esp_err_t get_config_param_blob(char* name, uint8_t** blob, size_t blob_len)
{
    nvs_handle_t nvs;

    esp_err_t err = nvs_open(PARAM_NAMESPACE, NVS_READONLY, &nvs);
    if (err == ESP_OK) {
        size_t len;
        if ( (err = nvs_get_blob(nvs, name, NULL, &len)) == ESP_OK) {
            if (len != blob_len) {
                nvs_close(nvs);
                return ESP_ERR_NVS_INVALID_LENGTH;
            }
            *blob = (uint8_t *)malloc(len);
            if (*blob == NULL) {
                nvs_close(nvs);
                return ESP_ERR_NO_MEM;
            }
            err = nvs_get_blob(nvs, name, *blob, &len);
            ESP_LOGI(TAG, "%s: %d", name, len);
        } else {
            return err;
        }
        nvs_close(nvs);
    } else {
        return err;
    }
    return ESP_OK;
}

void register_router(void)
{
    register_set_sta();
    register_set_sta_static();
    register_set_mac();
    register_set_ap();
    register_set_ap_ip();
    register_portmap();
    register_dhcp_reserve();
    register_show();
    register_disable_enable();
    register_set_web_password();
    register_bytes();
    register_pcap();
    register_set_led_gpio();
    register_acl();
}

/** Arguments used by 'set_sta' function */
static struct {
    struct arg_str* ssid;
    struct arg_str* password;
    struct arg_str* ent_username;
    struct arg_str* ent_identity;
    struct arg_end* end;
} set_sta_arg;

/* 'set_sta' command */
int set_sta(int argc, char **argv)
{
    esp_err_t err;
    nvs_handle_t nvs;

    int nerrors = arg_parse(argc, argv, (void **) &set_sta_arg);
    if (nerrors != 0) {
        arg_print_errors(stderr, set_sta_arg.end, argv[0]);
        return 1;
    }

    preprocess_string((char*)set_sta_arg.ssid->sval[0]);
    preprocess_string((char*)set_sta_arg.password->sval[0]);

    err = nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) {
        return err;
    }

    err = nvs_set_str(nvs, "ssid", set_sta_arg.ssid->sval[0]);
    if (err == ESP_OK) {
        err = nvs_set_str(nvs, "passwd", set_sta_arg.password->sval[0]);
        if (err == ESP_OK) {
            if (set_sta_arg.ent_username->count > 0) {
                err = nvs_set_str(nvs, "ent_username", set_sta_arg.ent_username->sval[0]);
            }
            else {
                err = nvs_set_str(nvs, "ent_username", "");
            }

            if (err == ESP_OK) {
                if (set_sta_arg.ent_identity->count > 0) {
                    err = nvs_set_str(nvs, "ent_identity", set_sta_arg.ent_identity->sval[0]);
                }
                else {
                    err = nvs_set_str(nvs, "ent_identity", "");
                }

        if (err == ESP_OK) {
            err = nvs_commit(nvs);
            if (err == ESP_OK) {
                ESP_LOGI(TAG, "STA settings %s/%s stored.", set_sta_arg.ssid->sval[0], set_sta_arg.password->sval[0]);
            }
        }
    }
        }
    }
    nvs_close(nvs);
    return err;
}

static void register_set_sta(void)
{
    set_sta_arg.ssid = arg_str1(NULL, NULL, "<ssid>", "SSID");
    set_sta_arg.password = arg_str1(NULL, NULL, "<passwd>", "Password");
    set_sta_arg.ent_username = arg_str0("-u", "--username", "<ent_username>", "Enterprise username");
    set_sta_arg.ent_identity = arg_str0("-a", "--anan", "<ent_identity>", "Enterprise identity");
    set_sta_arg.end = arg_end(2);

    const esp_console_cmd_t cmd = {
        .command = "set_sta",
        .help = "Set SSID and password of the STA interface",
        .hint = NULL,
        .func = &set_sta,
        .argtable = &set_sta_arg
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd) );
}


/** Arguments used by 'set_sta_static' function */
static struct {
    struct arg_str *static_ip;
    struct arg_str *subnet_mask;
    struct arg_str *gateway_addr;
    struct arg_end *end;
} set_sta_static_arg;

/* 'set_sta_static' command */
int set_sta_static(int argc, char **argv)
{
    esp_err_t err;
    nvs_handle_t nvs;

    int nerrors = arg_parse(argc, argv, (void **) &set_sta_static_arg);
    if (nerrors != 0) {
        arg_print_errors(stderr, set_sta_static_arg.end, argv[0]);
        return 1;
    }

    preprocess_string((char*)set_sta_static_arg.static_ip->sval[0]);
    preprocess_string((char*)set_sta_static_arg.subnet_mask->sval[0]);
    preprocess_string((char*)set_sta_static_arg.gateway_addr->sval[0]);

    err = nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) {
        return err;
    }

    err = nvs_set_str(nvs, "static_ip", set_sta_static_arg.static_ip->sval[0]);
    if (err == ESP_OK) {
        err = nvs_set_str(nvs, "subnet_mask", set_sta_static_arg.subnet_mask->sval[0]);
        if (err == ESP_OK) {
            err = nvs_set_str(nvs, "gateway_addr", set_sta_static_arg.gateway_addr->sval[0]);
            if (err == ESP_OK) {
              err = nvs_commit(nvs);
                if (err == ESP_OK) {
                    ESP_LOGI(TAG, "STA Static IP settings %s/%s/%s stored.", set_sta_static_arg.static_ip->sval[0], set_sta_static_arg.subnet_mask->sval[0], set_sta_static_arg.gateway_addr->sval[0]);
                }
            }
        }
    }
    nvs_close(nvs);
    return err;
}

static void register_set_sta_static(void)
{
    set_sta_static_arg.static_ip = arg_str1(NULL, NULL, "<ip>", "IP");
    set_sta_static_arg.subnet_mask = arg_str1(NULL, NULL, "<subnet>", "Subnet Mask");
    set_sta_static_arg.gateway_addr = arg_str1(NULL, NULL, "<gw>", "Gateway Address");
    set_sta_static_arg.end = arg_end(3);

    const esp_console_cmd_t cmd = {
        .command = "set_sta_static",
        .help = "Set Static IP for the STA interface",
        .hint = NULL,
        .func = &set_sta_static,
        .argtable = &set_sta_static_arg
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd) );
}

/** Arguments used by 'set_mac' function */
static struct {
    struct arg_int *mac0;
    struct arg_int *mac1;
    struct arg_int *mac2;
    struct arg_int *mac3;
    struct arg_int *mac4;
    struct arg_int *mac5;
    struct arg_end *end;
} set_mac_arg;

esp_err_t set_mac(const char *key, const char *interface, int argc, char **argv) {
    esp_err_t err;
    nvs_handle_t nvs;

    int nerrors = arg_parse(argc, argv, (void **) &set_mac_arg);
    if (nerrors != 0) {
        arg_print_errors(stderr, set_mac_arg.end, argv[0]);
        return 1;
    }

    err = nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) {
        return err;
    }

    uint8_t mac[] = {set_mac_arg.mac0->ival[0], set_mac_arg.mac1->ival[0], set_mac_arg.mac2->ival[0], set_mac_arg.mac3->ival[0], set_mac_arg.mac4->ival[0], set_mac_arg.mac5->ival[0]};
    err = nvs_set_blob(nvs, key, mac, sizeof(mac));
    if (err == ESP_OK) {
        err = nvs_commit(nvs);
        if (err == ESP_OK) {
            ESP_LOGI(TAG, "%s mac address %02X:%02X:%02X:%02X:%02X:%02X stored.", interface, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        }
    }
    nvs_close(nvs);
    return err;
}

int set_sta_mac(int argc, char **argv) {
    return set_mac("mac", "STA", argc, argv);
}

int set_ap_mac(int argc, char **argv) {
    return set_mac("ap_mac", "AP", argc, argv);
}

static void register_set_mac(void)
{
    set_mac_arg.mac0 = arg_int1(NULL, NULL, "<octet>", "First octet");
    set_mac_arg.mac1 = arg_int1(NULL, NULL, "<octet>", "Second octet");
    set_mac_arg.mac2 = arg_int1(NULL, NULL, "<octet>", "Third octet");
    set_mac_arg.mac3 = arg_int1(NULL, NULL, "<octet>", "Fourth octet");
    set_mac_arg.mac4 = arg_int1(NULL, NULL, "<octet>", "Fifth octet");
    set_mac_arg.mac5 = arg_int1(NULL, NULL, "<octet>", "Sixth octet");
    set_mac_arg.end = arg_end(6);

    const esp_console_cmd_t cmd_sta = {
        .command = "set_sta_mac",
        .help = "Set MAC address of the STA interface",
        .hint = NULL,
        .func = &set_sta_mac,
        .argtable = &set_mac_arg
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd_sta) );

    const esp_console_cmd_t cmd_ap = {
        .command = "set_ap_mac",
        .help = "Set MAC address of the AP interface",
        .hint = NULL,
        .func = &set_ap_mac,
        .argtable = &set_mac_arg
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd_ap) );
}

/** Arguments used by 'set_ap' function */
static struct {
    struct arg_str *ssid;
    struct arg_str *password;
    struct arg_end *end;
} set_ap_args;

/* 'set_ap' command */
int set_ap(int argc, char **argv)
{
    esp_err_t err;
    nvs_handle_t nvs;

    int nerrors = arg_parse(argc, argv, (void **) &set_ap_args);
    if (nerrors != 0) {
        arg_print_errors(stderr, set_ap_args.end, argv[0]);
        return 1;
    }

    preprocess_string((char*)set_ap_args.ssid->sval[0]);
    preprocess_string((char*)set_ap_args.password->sval[0]);

    if (strlen(set_ap_args.password->sval[0]) < 8) {
        printf("AP will be open (no passwd needed).\n");
    }

    err = nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) {
        return err;
    }

    err = nvs_set_str(nvs, "ap_ssid", set_ap_args.ssid->sval[0]);
    if (err == ESP_OK) {
        err = nvs_set_str(nvs, "ap_passwd", set_ap_args.password->sval[0]);
        if (err == ESP_OK) {
            err = nvs_commit(nvs);
            if (err == ESP_OK) {
                ESP_LOGI(TAG, "AP settings %s/%s stored.", set_ap_args.ssid->sval[0], set_ap_args.password->sval[0]);
            }
        }
    }
    nvs_close(nvs);
    return err;
}

static void register_set_ap(void)
{
    set_ap_args.ssid = arg_str1(NULL, NULL, "<ssid>", "SSID of AP");
    set_ap_args.password = arg_str1(NULL, NULL, "<passwd>", "Password of AP");
    set_ap_args.end = arg_end(2);

    const esp_console_cmd_t cmd = {
        .command = "set_ap",
        .help = "Set SSID and password of the SoftAP",
        .hint = NULL,
        .func = &set_ap,
        .argtable = &set_ap_args
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd) );
}

/** Arguments used by 'set_ap_ip' function */
static struct {
    struct arg_str *ap_ip_str;
    struct arg_end *end;
} set_ap_ip_arg;


/* 'set_ap_ip' command */
int set_ap_ip(int argc, char **argv)
{
    esp_err_t err;
    nvs_handle_t nvs;

    int nerrors = arg_parse(argc, argv, (void **) &set_ap_ip_arg);
    if (nerrors != 0) {
        arg_print_errors(stderr, set_ap_ip_arg.end, argv[0]);
        return 1;
    }

    preprocess_string((char*)set_ap_ip_arg.ap_ip_str->sval[0]);

    // Get current AP IP to check if network is changing
    char* old_ap_ip = NULL;
    get_config_param_str("ap_ip", &old_ap_ip);

    // Parse new IP
    uint32_t new_ip = esp_ip4addr_aton((char*)set_ap_ip_arg.ap_ip_str->sval[0]);

    // Check if we're changing to a different Class C network
    bool clear_config = false;
    if (old_ap_ip != NULL) {
        uint32_t old_ip = esp_ip4addr_aton(old_ap_ip);

        // Compare first 3 octets (Class C network: /24)
        if ((old_ip & 0xFFFFFF00) != (new_ip & 0xFFFFFF00)) {
            clear_config = true;
            ESP_LOGI(TAG, "AP IP network changed from %s to %s - clearing reservations and port mappings",
                     old_ap_ip, set_ap_ip_arg.ap_ip_str->sval[0]);
        }
        free(old_ap_ip);
    }

    err = nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) {
        return err;
    }

    err = nvs_set_str(nvs, "ap_ip", set_ap_ip_arg.ap_ip_str->sval[0]);
    if (err == ESP_OK) {
        err = nvs_commit(nvs);
        if (err == ESP_OK) {
            ESP_LOGI(TAG, "AP IP address %s stored.", set_ap_ip_arg.ap_ip_str->sval[0]);
        }
    }
    nvs_close(nvs);

    // Clear DHCP reservations and port mappings if network changed
    if (clear_config && err == ESP_OK) {
        clear_all_dhcp_reservations();
        clear_all_portmaps();
    }

    return err;
}

static void register_set_ap_ip(void)
{
    set_ap_ip_arg.ap_ip_str = arg_str1(NULL, NULL, "<ip>", "IP");
    set_ap_ip_arg.end = arg_end(1);

    const esp_console_cmd_t cmd = {
        .command = "set_ap_ip",
        .help = "Set IP for the AP interface",
        .hint = NULL,
        .func = &set_ap_ip,
        .argtable = &set_ap_ip_arg
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd) );
}

/* 'disable' command */
static int disable_webserver(int argc, char **argv)
{
    esp_err_t err;
    nvs_handle_t nvs;

    err = nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) {
        return err;
    }

    err = nvs_set_str(nvs, "lock", "1");
    if (err == ESP_OK) {
        err = nvs_commit(nvs);
        if (err == ESP_OK) {
            ESP_LOGI(TAG, "Web interface disabled. Use 'enable' command to re-enable.");
            printf("Web interface will be disabled after reboot.\n");
            printf("Use 'enable' command to re-enable it.\n");
        }
    }
    nvs_close(nvs);
    return err;
}

/* 'enable' command */
static int enable_webserver(int argc, char **argv)
{
    esp_err_t err;
    nvs_handle_t nvs;

    err = nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) {
        return err;
    }

    err = nvs_set_str(nvs, "lock", "0");
    if (err == ESP_OK) {
        err = nvs_commit(nvs);
        if (err == ESP_OK) {
            ESP_LOGI(TAG, "Web interface enabled.");
            printf("Web interface will be enabled after reboot.\n");
        }
    }
    nvs_close(nvs);
    return err;
}

static void register_disable_enable(void)
{
    const esp_console_cmd_t disable_cmd = {
        .command = "disable",
        .help = "Disable the web interface",
        .hint = NULL,
        .func = &disable_webserver,
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&disable_cmd) );

    const esp_console_cmd_t enable_cmd = {
        .command = "enable",
        .help = "Enable the web interface",
        .hint = NULL,
        .func = &enable_webserver,
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&enable_cmd) );
}

/* 'set_web_password' command */
static int set_web_password_cmd(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: set_web_password <password>\n");
        printf("Use empty string \"\" to disable password protection\n");
        return 1;
    }

    esp_err_t err;
    nvs_handle_t nvs;

    err = nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) {
        printf("Failed to open NVS\n");
        return err;
    }

    err = nvs_set_str(nvs, "web_password", argv[1]);
    if (err == ESP_OK) {
        err = nvs_commit(nvs);
        if (err == ESP_OK) {
            if (argv[1][0] == '\0') {
                ESP_LOGI(TAG, "Web password protection disabled.");
                printf("Password protection disabled.\n");
            } else {
                ESP_LOGI(TAG, "Web password updated.");
                printf("Password updated successfully.\n");
            }
        }
    } else {
        printf("Failed to set password\n");
    }
    nvs_close(nvs);
    return err;
}

static void register_set_web_password(void)
{
    const esp_console_cmd_t cmd = {
        .command = "set_web_password",
        .help = "Set web interface password (empty string to disable)",
        .hint = NULL,
        .func = &set_web_password_cmd,
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd) );
}

/** Arguments used by 'portmap' function */
static struct {
    struct arg_str *add_del;
    struct arg_str *TCP_UDP;
    struct arg_int *ext_port;
    struct arg_str *int_ip;
    struct arg_int *int_port;
    struct arg_end *end;
} portmap_args;

/* 'portmap' command */
int portmap(int argc, char **argv)
{
    int nerrors = arg_parse(argc, argv, (void **) &portmap_args);
    if (nerrors != 0) {
        arg_print_errors(stderr, portmap_args.end, argv[0]);
        return 1;
    }

    bool add;
    if (strcmp((char *)portmap_args.add_del->sval[0], "add")== 0) {
        add = true;
    } else if (strcmp((char *)portmap_args.add_del->sval[0], "del")== 0) {
        add = false;
    } else {
        printf("Must be 'add' or 'del'\n");
        return 1;
    }

    uint8_t tcp_udp;
    if (strcmp((char *)portmap_args.TCP_UDP->sval[0], "TCP")== 0) {
        tcp_udp = PROTO_TCP;
    } else if (strcmp((char *)portmap_args.TCP_UDP->sval[0], "UDP")== 0) {
        tcp_udp = PROTO_UDP;
    } else {
        printf("Must be 'TCP' or 'UDP'\n");
        return 1;
    }

    uint16_t ext_port = portmap_args.ext_port->ival[0];
    uint32_t int_ip = esp_ip4addr_aton((char *)portmap_args.int_ip->sval[0]);
    uint16_t int_port = portmap_args.int_port->ival[0];

    //printf("portmap %d %d %x %d %x %d\n", add, tcp_udp, my_ip, ext_port, int_ip, int_port);

    if (add) {
        add_portmap(tcp_udp, ext_port, int_ip, int_port);
    } else {
        del_portmap(tcp_udp, ext_port);
    }

    return ESP_OK;
}

static void register_portmap(void)
{
    portmap_args.add_del = arg_str1(NULL, NULL, "[add|del]", "add or delete portmapping");
    portmap_args.TCP_UDP = arg_str1(NULL, NULL, "[TCP|UDP]", "TCP or UDP port");
    portmap_args.ext_port = arg_int1(NULL, NULL, "<ext_portno>", "external port number");
    portmap_args.int_ip = arg_str1(NULL, NULL, "<int_ip>", "internal IP");
    portmap_args.int_port = arg_int1(NULL, NULL, "<int_portno>", "internal port number");
    portmap_args.end = arg_end(5);

    const esp_console_cmd_t cmd = {
        .command = "portmap",
        .help = "Add or delete a portmapping to the router",
        .hint = NULL,
        .func = &portmap,
        .argtable = &portmap_args
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd) );
}

/* 'show' command arguments */
static struct {
    struct arg_str *type;
    struct arg_end *end;
} show_args;

/* 'show' command implementation */
static int show(int argc, char **argv)
{
    int nerrors = arg_parse(argc, argv, (void **) &show_args);
    if (nerrors != 0) {
        arg_print_errors(stderr, show_args.end, argv[0]);
        return 1;
    }

    if (show_args.type->count == 0) {
        printf("Usage: show <status|config|mappings|acl>\n");
        printf("  status   - Show router status (connection, clients, memory)\n");
        printf("  config   - Show router configuration (AP/STA settings)\n");
        printf("  mappings - Show DHCP pool, reservations and port mappings\n");
        printf("  acl      - Show firewall ACL rules\n");
        return 1;
    }

    const char *type = show_args.type->sval[0];

    if (strcmp(type, "status") == 0) {
        // Show status
        printf("Router Status:\n");
        printf("==============\n");
        
        // Connection status
        printf("Uplink AP: %sconnected\n", ap_connect ? "" : "not ");
        if (ap_connect) {
            ip4_addr_t addr;
            addr.addr = my_ip;
            printf("Uplink IP: " IPSTR "\n", IP2STR(&addr));
        } else {
            printf("Uplink IP: none\n");
        }

        // Byte counts
        printf("Bytes sent/received: %" PRIu64 " / %" PRIu64 " bytes\n", get_sta_bytes_sent(), get_sta_bytes_received());

        // Free heap
        printf("Free heap: %lu bytes\n", (unsigned long)esp_get_free_heap_size());

        // Connected clients
        printf("Connected clients: %u\n", connect_count);
        if (connect_count > 0) {
            connected_client_t clients[8];
            int count = get_connected_clients(clients, 8);
            
            if (count > 0) {
                printf("\nClient Details:\n");
                printf("MAC Address       IP Address       Device Name\n");
                printf("----------------  ---------------  ------------------\n");
                
                for (int i = 0; i < count; i++) {
                    char mac_str[18];
                    sprintf(mac_str, "%02X:%02X:%02X:%02X:%02X:%02X",
                            clients[i].mac[0], clients[i].mac[1], clients[i].mac[2],
                            clients[i].mac[3], clients[i].mac[4], clients[i].mac[5]);
                    
                    char ip_str[16] = "N/A";
                    if (clients[i].has_ip) {
                        ip4_addr_t addr;
                        addr.addr = clients[i].ip;
                        sprintf(ip_str, IPSTR, IP2STR(&addr));
                    }
                    
                    printf("%-17s  %-15s  %s\n", mac_str, ip_str, clients[i].name);
                }
            }
        }
        
    } else if (strcmp(type, "config") == 0) {
        // Show config
        char* ssid = NULL;
        char* ent_username = NULL;
        char* ent_identity = NULL;
        char* passwd = NULL;
        char* static_ip = NULL;
        char* subnet_mask = NULL;
        char* gateway_addr = NULL;
        char* ap_ssid = NULL;
        char* ap_passwd = NULL;

        get_config_param_str("ssid", &ssid);
        get_config_param_str("ent_username", &ent_username);
        get_config_param_str("ent_identity", &ent_identity);
        get_config_param_str("passwd", &passwd);
        get_config_param_str("static_ip", &static_ip);
        get_config_param_str("subnet_mask", &subnet_mask);
        get_config_param_str("gateway_addr", &gateway_addr);
        get_config_param_str("ap_ssid", &ap_ssid);
        get_config_param_str("ap_passwd", &ap_passwd);

        printf("Router Configuration:\n");
        printf("====================\n");
        
        printf("STA Settings:\n");
        printf("  SSID: %s\n", ssid != NULL ? ssid : "<undef>");
        printf("  Password: %s\n", passwd != NULL ? passwd : "<undef>");
        if ((ent_username != NULL) && (strlen(ent_username) > 0)) {
            printf("  Enterprise Username: %s\n", ent_username);
            if ((ent_identity != NULL) && (strlen(ent_identity) > 0)) {
                printf("  Enterprise Identity: %s\n", ent_identity);
            }
        } else {
            printf("  Enterprise: <not active>\n");
        }
        
        if (static_ip != NULL) {
            printf("  Static IP: %s\n", static_ip);
            printf("  Subnet Mask: %s\n", subnet_mask != NULL ? subnet_mask : "<undef>");
            printf("  Gateway: %s\n", gateway_addr != NULL ? gateway_addr : "<undef>");
        } else {
            printf("  Static IP: <not configured>\n");
        }
        
        printf("\nAP Settings:\n");
        printf("  SSID: %s\n", ap_ssid != NULL ? ap_ssid : "<undef>");
        printf("  Password: %s\n", ap_passwd != NULL ? ap_passwd : "<undef>");
        ip4_addr_t addr;
        addr.addr = my_ap_ip;
        printf("  IP Address: " IPSTR "\n", IP2STR(&addr));

        // Cleanup
        if (ssid != NULL) free(ssid);
        if (ent_username != NULL) free(ent_username);
        if (ent_identity != NULL) free(ent_identity);
        if (passwd != NULL) free(passwd);
        if (static_ip != NULL) free(static_ip);
        if (subnet_mask != NULL) free(subnet_mask);
        if (gateway_addr != NULL) free(gateway_addr);
        if (ap_ssid != NULL) free(ap_ssid);
        if (ap_passwd != NULL) free(ap_passwd);
        
    } else if (strcmp(type, "mappings") == 0) {
        // Show mappings
        printf("Network Mappings:\n");
        printf("=================\n");

        printf("\nDHCP Pool:\n");
        print_dhcp_pool();

        printf("\nDHCP Reservations:\n");
        print_dhcp_reservations();

        printf("\nPort Mappings:\n");
        print_portmap_tab();

    } else if (strcmp(type, "acl") == 0) {
        // Show ACL rules with device names
        printf("Firewall ACL Rules:\n");
        printf("===================\n");

        for (int i = 0; i < MAX_ACL_LISTS; i++) {
            acl_print_with_names(i);
        }

    } else {
        printf("Invalid parameter. Use: show <status|config|mappings|acl>\n");
        return 1;
    }

    return 0;
}

static void register_show(void)
{
    show_args.type = arg_str1(NULL, NULL, "[status|config|mappings|acl]", "Type of information");
    show_args.end = arg_end(1);

    const esp_console_cmd_t cmd = {
        .command = "show",
        .help = "Show router status, config, mappings or ACL rules",
        .hint = NULL,
        .func = &show,
        .argtable = &show_args
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd) );
}

/** Arguments used by 'dhcp_reserve' function */
static struct {
    struct arg_str *add_del;
    struct arg_str *mac_addr;
    struct arg_str *ip_addr;
    struct arg_str *name;
    struct arg_end *end;
} dhcp_reserve_args;

/* 'dhcp_reserve' command */
int dhcp_reserve(int argc, char **argv)
{
    int nerrors = arg_parse(argc, argv, (void **) &dhcp_reserve_args);
    if (nerrors != 0) {
        arg_print_errors(stderr, dhcp_reserve_args.end, argv[0]);
        return 1;
    }

    bool add;
    if (strcmp((char *)dhcp_reserve_args.add_del->sval[0], "add") == 0) {
        add = true;
    } else if (strcmp((char *)dhcp_reserve_args.add_del->sval[0], "del") == 0) {
        add = false;
    } else {
        printf("Must be 'add' or 'del'\n");
        return 1;
    }

    // Parse MAC address (AA:BB:CC:DD:EE:FF or AA-BB-CC-DD-EE-FF)
    unsigned int mac[6];
    const char *mac_str = dhcp_reserve_args.mac_addr->sval[0];
    if (sscanf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x",
               &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6 &&
        sscanf(mac_str, "%02x-%02x-%02x-%02x-%02x-%02x",
               &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6) {
        printf("Invalid MAC address format. Use AA:BB:CC:DD:EE:FF\n");
        return 1;
    }

    uint8_t mac_bytes[6];
    for (int i = 0; i < 6; i++) {
        mac_bytes[i] = (uint8_t)mac[i];
    }

    if (add) {
        // Parse IP address
        uint32_t ip = esp_ip4addr_aton((char *)dhcp_reserve_args.ip_addr->sval[0]);
        if (ip == 0) {
            printf("Invalid IP address\n");
            return 1;
        }

        // Get optional name
        const char *name = NULL;
        if (dhcp_reserve_args.name->count > 0) {
            name = dhcp_reserve_args.name->sval[0];
        }

        esp_err_t err = add_dhcp_reservation(mac_bytes, ip, name);
        if (err == ESP_OK) {
            printf("DHCP reservation added\n");
        } else if (err == ESP_ERR_NO_MEM) {
            printf("No more slots available for DHCP reservations\n");
            return 1;
        } else {
            printf("Failed to add DHCP reservation\n");
            return 1;
        }
    } else {
        esp_err_t err = del_dhcp_reservation(mac_bytes);
        if (err == ESP_OK) {
            printf("DHCP reservation deleted\n");
        } else {
            printf("Failed to delete DHCP reservation\n");
            return 1;
        }
    }

    return ESP_OK;
}

static void register_dhcp_reserve(void)
{
    dhcp_reserve_args.add_del = arg_str1(NULL, NULL, "[add|del]", "add or delete reservation");
    dhcp_reserve_args.mac_addr = arg_str1(NULL, NULL, "<mac>", "MAC address (AA:BB:CC:DD:EE:FF)");
    dhcp_reserve_args.ip_addr = arg_str0(NULL, NULL, "<ip>", "IP address (required for add)");
    dhcp_reserve_args.name = arg_str0("-n", "--name", "<name>", "optional device name");
    dhcp_reserve_args.end = arg_end(4);

    const esp_console_cmd_t cmd = {
        .command = "dhcp_reserve",
        .help = "Add or delete a DHCP reservation",
        .hint = NULL,
        .func = &dhcp_reserve,
        .argtable = &dhcp_reserve_args
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd) );
}

/* 'bytes' command */
static struct {
    struct arg_str* action;
    struct arg_end* end;
} bytes_args;

static int bytes(int argc, char **argv)
{
    int nerrors = arg_parse(argc, argv, (void **) &bytes_args);
    if (nerrors != 0) {
        arg_print_errors(stderr, bytes_args.end, argv[0]);
        return 1;
    }

    if (bytes_args.action->count == 0) {
        // Show current byte counts
        printf("STA Interface Byte Counts:\n");
        printf("  Sent:     %" PRIu64 " bytes\n", get_sta_bytes_sent());
        printf("  Received: %" PRIu64 " bytes\n", get_sta_bytes_received());
        return 0;
    }

    const char *action = bytes_args.action->sval[0];
    if (strcmp(action, "reset") == 0) {
        reset_sta_byte_counts();
        printf("Byte counts reset to zero\n");
    } else {
        printf("Usage: bytes [reset]\n");
        printf("  bytes     - Show current byte counts\n");
        printf("  bytes reset - Reset byte counts to zero\n");
        return 1;
    }

    return 0;
}

static void register_bytes(void)
{
    bytes_args.action = arg_str0(NULL, NULL, "[reset]", "reset byte counts or show current counts");
    bytes_args.end = arg_end(1);

    const esp_console_cmd_t cmd = {
        .command = "bytes",
        .help = "Show or reset STA interface byte counts",
        .hint = NULL,
        .func = &bytes,
        .argtable = &bytes_args
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd) );
}

/* 'pcap' command arguments */
static struct {
    struct arg_str* action;
    struct arg_str* mode;
    struct arg_int* snaplen;
    struct arg_end* end;
} pcap_args;

/* 'pcap' command implementation */
static int pcap(int argc, char **argv)
{
    int nerrors = arg_parse(argc, argv, (void **) &pcap_args);
    if (nerrors != 0) {
        arg_print_errors(stderr, pcap_args.end, argv[0]);
        return 1;
    }

    if (pcap_args.action->count == 0) {
        printf("Usage: pcap <action> [args]\n");
        printf("  mode [off|acl|promisc] - Get or set capture mode\n");
        printf("    off      - Capture disabled\n");
        printf("    acl      - Capture ACL_MONITOR flagged packets (any interface)\n");
        printf("    promisc  - Capture all AP client traffic (not STA)\n");
        printf("  status     - Show capture status\n");
        printf("  snaplen [n]- Get or set max capture bytes (64-1600)\n");
        printf("  start      - Legacy: enable promiscuous mode\n");
        printf("  stop       - Legacy: disable capture\n");
        return 1;
    }

    const char *action = pcap_args.action->sval[0];

    if (strcmp(action, "mode") == 0) {
        if (pcap_args.mode->count > 0) {
            const char *mode_str = pcap_args.mode->sval[0];
            if (strcmp(mode_str, "off") == 0) {
                pcap_set_mode(PCAP_MODE_OFF);
                printf("Capture mode: off\n");
            } else if (strcmp(mode_str, "acl") == 0) {
                pcap_set_mode(PCAP_MODE_ACL_MONITOR);
                printf("Capture mode: acl-monitor\n");
                printf("Only packets matching ACL rules with +M flag will be captured (any interface)\n");
            } else if (strcmp(mode_str, "promisc") == 0 || strcmp(mode_str, "promiscuous") == 0) {
                pcap_set_mode(PCAP_MODE_PROMISCUOUS);
                printf("Capture mode: promiscuous\n");
                printf("All AP client traffic will be captured (STA excluded)\n");
            } else {
                printf("Invalid mode. Use: off, acl, or promisc\n");
                return 1;
            }
            printf("Connect Wireshark to TCP port 19000\n");
        } else {
            printf("Current mode: %s\n", pcap_mode_to_string(pcap_get_mode()));
        }
    } else if (strcmp(action, "start") == 0) {
        // Legacy: start = promiscuous mode
        pcap_set_mode(PCAP_MODE_PROMISCUOUS);
        printf("PCAP capture started in promiscuous mode (snaplen=%d)\n", pcap_get_snaplen());
        printf("Connect Wireshark to TCP port 19000\n");
    } else if (strcmp(action, "stop") == 0) {
        // Legacy: stop = off mode
        pcap_set_mode(PCAP_MODE_OFF);
        printf("PCAP capture stopped\n");
    } else if (strcmp(action, "snaplen") == 0) {
        if (pcap_args.snaplen->count > 0) {
            int val = pcap_args.snaplen->ival[0];
            if (pcap_set_snaplen((uint16_t)val)) {
                printf("Snaplen set to %d bytes\n", pcap_get_snaplen());
            } else {
                printf("Error: snaplen must be between 64 and 1600\n");
                return 1;
            }
        } else {
            printf("Current snaplen: %d bytes\n", pcap_get_snaplen());
        }
    } else if (strcmp(action, "status") == 0) {
        printf("PCAP Capture Status:\n");
        printf("====================\n");
        printf("Mode:     %s\n", pcap_mode_to_string(pcap_get_mode()));
        printf("Client:   %s\n", pcap_client_connected() ? "connected" : "not connected");
        printf("Snaplen:  %d bytes\n", pcap_get_snaplen());

        size_t used, total;
        pcap_get_buffer_usage(&used, &total);
        printf("Buffer:   %u / %u bytes (%.1f%%)\n",
               (unsigned)used, (unsigned)total,
               total > 0 ? (100.0f * used / total) : 0.0f);

        printf("Captured: %lu packets\n", (unsigned long)pcap_get_captured_count());
        printf("Dropped:  %lu packets\n", (unsigned long)pcap_get_dropped_count());
        printf("\nConnection: nc <esp32_ip> 19000 | wireshark -k -i -\n");
    } else {
        printf("Invalid action. Use: pcap <mode|status|snaplen|start|stop>\n");
        return 1;
    }

    return 0;
}

static void register_pcap(void)
{
    pcap_args.action = arg_str1(NULL, NULL, "<action>", "mode|status|snaplen|start|stop");
    pcap_args.mode = arg_str0(NULL, NULL, "<mode>", "off|acl|promisc");
    pcap_args.snaplen = arg_int0(NULL, NULL, "<bytes>", "snaplen value (64-1600)");
    pcap_args.end = arg_end(3);

    const esp_console_cmd_t cmd = {
        .command = "pcap",
        .help = "Control PCAP packet capture (TCP port 19000)",
        .hint = NULL,
        .func = &pcap,
        .argtable = &pcap_args
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd) );
}

/* 'set_led_gpio' command */
static int set_led_gpio_cmd(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: set_led_gpio <gpio_number|none>\n");
        printf("  gpio_number: GPIO pin number (0-48)\n");
        printf("  none: disable LED status blinking\n");
        printf("\nCurrent setting: ");
        if (led_gpio < 0) {
            printf("none (disabled)\n");
        } else {
            printf("GPIO %d\n", led_gpio);
        }
        return 0;
    }

    esp_err_t err;
    nvs_handle_t nvs;
    int gpio_num;

    // Parse argument
    if (strcasecmp(argv[1], "none") == 0 || strcmp(argv[1], "-1") == 0) {
        gpio_num = -1;
    } else {
        char *endptr;
        gpio_num = strtol(argv[1], &endptr, 10);
        if (*endptr != '\0' || gpio_num < 0 || gpio_num > 48) {
            printf("Invalid GPIO number. Use 0-48 or 'none'.\n");
            return 1;
        }
    }

    err = nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs);
    if (err != ESP_OK) {
        printf("Failed to open NVS\n");
        return err;
    }

    err = nvs_set_i32(nvs, "led_gpio", gpio_num);
    if (err == ESP_OK) {
        err = nvs_commit(nvs);
        if (err == ESP_OK) {
            if (gpio_num < 0) {
                ESP_LOGI(TAG, "LED GPIO disabled.");
                printf("LED status blinking disabled.\n");
            } else {
                ESP_LOGI(TAG, "LED GPIO set to %d.", gpio_num);
                printf("LED status blinking set to GPIO %d.\n", gpio_num);
            }
            printf("Restart the device for changes to take effect.\n");
        }
    } else {
        printf("Failed to save setting\n");
    }
    nvs_close(nvs);
    return err;
}

static void register_set_led_gpio(void)
{
    const esp_console_cmd_t cmd = {
        .command = "set_led_gpio",
        .help = "Set GPIO for status LED blinking (use 'none' to disable)",
        .hint = NULL,
        .func = &set_led_gpio_cmd,
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd) );
}

/**
 * @brief Format IP address with device name for /32 addresses
 * If the IP has a full /32 mask and a matching DHCP reservation with a name,
 * returns the device name. Otherwise returns the formatted IP/mask.
 */
static char* acl_format_ip_with_name(uint32_t ip, uint32_t mask, char* buf, size_t buf_len)
{
    /* Check for "any" (0.0.0.0/0) */
    if (ip == 0 && mask == 0) {
        snprintf(buf, buf_len, "any");
        return buf;
    }

    /* For /32 addresses, try to look up device name */
    if (mask == 0xFFFFFFFF) {
        const char* name = lookup_device_name_by_ip(ip);
        if (name != NULL) {
            snprintf(buf, buf_len, "%s", name);
            return buf;
        }
    }

    /* Fall back to standard IP formatting */
    return acl_format_ip(ip, mask, buf, buf_len);
}

/**
 * @brief Parse IP address or device name for ACL rules
 * First tries to parse as IP/CIDR, then tries to resolve as device name.
 * Device names are resolved to /32 addresses.
 */
static bool acl_parse_ip_or_name(const char* str, uint32_t* ip, uint32_t* mask)
{
    /* First try standard IP parsing */
    if (acl_parse_ip(str, ip, mask)) {
        return true;
    }

    /* Try to resolve as device name (case-insensitive) */
    if (resolve_device_name_to_ip(str, ip)) {
        *mask = 0xFFFFFFFF;  /* /32 for device names */
        return true;
    }

    return false;
}

/**
 * @brief Print ACL rules with device names for /32 addresses
 */
static void acl_print_with_names(uint8_t acl_no)
{
    if (acl_no >= MAX_ACL_LISTS) {
        printf("Invalid ACL list number\n");
        return;
    }

    printf("\nACL: %s\n", acl_get_name(acl_no));
    printf("==========\n");

    acl_stats_t *stats = acl_get_stats(acl_no);
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

    acl_entry_t *rules = acl_get_rules(acl_no);
    for (int i = 0; i < MAX_ACL_ENTRIES; i++) {
        acl_entry_t *rule = &rules[i];
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

        /* Format IP addresses with device names */
        char src_str[24], dest_str[24];
        acl_format_ip_with_name(rule->src, rule->s_mask, src_str, sizeof(src_str));
        acl_format_ip_with_name(rule->dest, rule->d_mask, dest_str, sizeof(dest_str));

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

/* 'acl' command implementation */
static int acl_cmd(int argc, char **argv)
{
    if (argc < 2) {
        printf("Usage: acl <list> <action> [params...]\n");
        printf("Lists: from_sta, to_sta, from_ap, to_ap\n");
        printf("\nActions:\n");
        printf("  acl <list> clear              - Clear all rules from list\n");
        printf("  acl <list> clear_stats        - Clear statistics for list\n");
        printf("  acl <list> del <idx>          - Delete rule at index\n");
        printf("  acl <list> <proto> <src> [<s_port>] <dst> [<d_port>] <action>\n");
        printf("\nProtocols: IP, TCP, UDP, ICMP\n");
        printf("Addresses: IP/mask, 'any', or device name from DHCP reservations\n");
        printf("Ports:     Port number or '*' for any (TCP/UDP only)\n");
        printf("Actions:   allow, deny, allow_monitor, deny_monitor\n");
        printf("\nExamples:\n");
        printf("  acl from_sta clear\n");
        printf("  acl from_sta IP any 255.255.255.255 allow\n");
        printf("  acl from_sta UDP any any any 53 allow\n");
        printf("  acl from_sta TCP any 22 192.168.4.0/24 * deny\n");
        printf("  acl from_sta IP any MyPhone deny      # Use device name\n");
        printf("  acl from_sta IP any any deny          # Block all at end\n");
        printf("  acl from_sta del 0                    # Delete first rule\n");
        return 0;
    }

    /* Parse list name */
    int list_no = acl_parse_name(argv[1]);
    if (list_no < 0) {
        printf("Invalid ACL list: %s\n", argv[1]);
        printf("Use: from_sta, to_sta, from_ap, to_ap\n");
        return 1;
    }

    if (argc < 3) {
        printf("Missing action. Use: clear, clear_stats, del, or <proto> <src> <dst> <action>\n");
        return 1;
    }

    /* Handle 'clear' action */
    if (strcmp(argv[2], "clear") == 0) {
        acl_clear(list_no);
        save_acl_rules();
        printf("ACL list %s cleared.\n", acl_get_name(list_no));
        return 0;
    }

    /* Handle 'clear_stats' action */
    if (strcmp(argv[2], "clear_stats") == 0) {
        acl_clear_stats(list_no);
        printf("ACL statistics for %s cleared.\n", acl_get_name(list_no));
        return 0;
    }

    /* Handle 'del' action */
    if (strcmp(argv[2], "del") == 0) {
        if (argc < 4) {
            printf("Usage: acl <list> del <index>\n");
            return 1;
        }
        int idx = atoi(argv[3]);
        if (idx < 0 || idx >= MAX_ACL_ENTRIES) {
            printf("Invalid rule index: %d (0-%d)\n", idx, MAX_ACL_ENTRIES - 1);
            return 1;
        }
        if (acl_delete(list_no, idx)) {
            save_acl_rules();
            printf("Deleted rule %d from %s\n", idx, acl_get_name(list_no));
        } else {
            printf("No rule at index %d\n", idx);
        }
        return 0;
    }

    /* Parse as add rule: <proto> <src> [<s_port>] <dst> [<d_port>] <action> */
    const char *proto_str = argv[2];
    uint8_t proto;

    if (strcasecmp(proto_str, "IP") == 0) {
        proto = 0;
    } else if (strcasecmp(proto_str, "ICMP") == 0) {
        proto = 1;
    } else if (strcasecmp(proto_str, "TCP") == 0) {
        proto = 6;
    } else if (strcasecmp(proto_str, "UDP") == 0) {
        proto = 17;
    } else {
        printf("Invalid protocol: %s (use IP, ICMP, TCP, UDP)\n", proto_str);
        return 1;
    }

    /* For TCP/UDP, we expect: proto src s_port dst d_port action (7 args total)
       For IP/ICMP, we expect: proto src dst action (5 args total)
       But we also support: proto src dst action (no ports) for TCP/UDP */

    uint32_t src_ip, src_mask, dst_ip, dst_mask;
    uint16_t s_port = 0, d_port = 0;
    uint8_t allow;
    int arg_idx = 3;

    /* Parse source (IP/CIDR, 'any', or device name) */
    if (arg_idx >= argc) {
        printf("Missing source address\n");
        return 1;
    }
    if (!acl_parse_ip_or_name(argv[arg_idx], &src_ip, &src_mask)) {
        printf("Invalid source address or device name: %s\n", argv[arg_idx]);
        return 1;
    }
    arg_idx++;

    /* For TCP/UDP, check if next arg is a port */
    if ((proto == 6 || proto == 17) && arg_idx < argc) {
        if (strcmp(argv[arg_idx], "*") == 0 || strcmp(argv[arg_idx], "any") == 0) {
            s_port = 0;
            arg_idx++;
        } else if (argv[arg_idx][0] >= '0' && argv[arg_idx][0] <= '9') {
            s_port = atoi(argv[arg_idx]);
            arg_idx++;
        }
        /* If not a port-like value, treat as destination */
    }

    /* Parse destination (IP/CIDR, 'any', or device name) */
    if (arg_idx >= argc) {
        printf("Missing destination address\n");
        return 1;
    }
    if (!acl_parse_ip_or_name(argv[arg_idx], &dst_ip, &dst_mask)) {
        printf("Invalid destination address or device name: %s\n", argv[arg_idx]);
        return 1;
    }
    arg_idx++;

    /* For TCP/UDP, check if next arg is a port */
    if ((proto == 6 || proto == 17) && arg_idx < argc) {
        if (strcmp(argv[arg_idx], "*") == 0 || strcmp(argv[arg_idx], "any") == 0) {
            d_port = 0;
            arg_idx++;
        } else if (argv[arg_idx][0] >= '0' && argv[arg_idx][0] <= '9') {
            d_port = atoi(argv[arg_idx]);
            arg_idx++;
        }
        /* If not a port-like value, treat as action */
    }

    /* Parse action */
    if (arg_idx >= argc) {
        printf("Missing action (allow, deny, allow_monitor, deny_monitor)\n");
        return 1;
    }
    const char *action_str = argv[arg_idx];

    if (strcasecmp(action_str, "allow") == 0) {
        allow = ACL_ALLOW;
    } else if (strcasecmp(action_str, "deny") == 0) {
        allow = ACL_DENY;
    } else if (strcasecmp(action_str, "allow_monitor") == 0) {
        allow = ACL_ALLOW | ACL_MONITOR;
    } else if (strcasecmp(action_str, "deny_monitor") == 0) {
        allow = ACL_DENY | ACL_MONITOR;
    } else {
        printf("Invalid action: %s (use allow, deny, allow_monitor, deny_monitor)\n", action_str);
        return 1;
    }

    /* Add the rule */
    if (acl_add(list_no, src_ip, src_mask, dst_ip, dst_mask, proto, s_port, d_port, allow)) {
        save_acl_rules();
        printf("Rule added to %s\n", acl_get_name(list_no));
    } else {
        printf("Failed to add rule (list may be full)\n");
        return 1;
    }

    return 0;
}

static void register_acl(void)
{
    const esp_console_cmd_t cmd = {
        .command = "acl",
        .help = "Manage firewall ACL rules",
        .hint = NULL,
        .func = &acl_cmd,
    };
    ESP_ERROR_CHECK( esp_console_cmd_register(&cmd) );
}
