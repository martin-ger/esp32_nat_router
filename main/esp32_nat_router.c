/* ESP32 NAT Router - Main application
 *
 * Entry point, global variable definitions, WiFi/Ethernet initialization,
 * event handlers, LED status thread, and console REPL.
 *
 * Modular source files:
 *   portmap.c       - Port mapping (NAPT) table management
 *   dhcp_manager.c  - DHCP reservation management
 *   acl_nvs.c       - ACL firewall rule persistence
 *   vpn_manager.c   - WireGuard VPN connection management
 *   netif_hooks.c   - Network interface hooks (byte counting, ACL, PCAP, MSS/PMTU)
 */

#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include "esp_system.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_console.h"
#include "esp_vfs_dev.h"
#include "driver/gpio.h"
#include "driver/uart.h"
#include "driver/uart_vfs.h"
#include "driver/usb_serial_jtag.h"
#include "driver/usb_serial_jtag_vfs.h"
#include "linenoise/linenoise.h"
#include "argtable3/argtable3.h"
#include "esp_vfs_fat.h"
#include "nvs.h"
#include "nvs_flash.h"

#include "freertos/event_groups.h"
#include "esp_wifi.h"
#if !CONFIG_ETH_UPLINK
#include "esp_eap_client.h"
#endif
#if CONFIG_ETH_UPLINK
#include "esp_eth.h"
#endif

#include "lwip/opt.h"
#include "lwip/err.h"
#include "lwip/sys.h"

#include "dhcpserver/dhcpserver.h"
#include "dhcpserver/dhcpserver_options.h"

#include "cmd_decl.h"
#include <esp_http_server.h>

#if !IP_NAPT
#error "IP_NAPT must be defined"
#endif
#include "lwip/lwip_napt.h"

#include "router_globals.h"
#include "lwip/ip_addr.h"
#include "esp_netif.h"
#include "pcap_capture.h"
#include "remote_console.h"
#include "oled_display.h"

// Byte counting variables
uint64_t sta_bytes_sent = 0;
uint64_t sta_bytes_received = 0;

// TTL override for STA upstream (0 = disabled/no change)
uint8_t sta_ttl_override = 0;

// MSS clamp for AP interface (0 = disabled, otherwise max MSS in bytes)
uint16_t ap_mss_clamp = 0;

// Path MTU for AP clients: send ICMP Fragmentation Needed when a DF-flagged packet
// from a client exceeds this size (0 = disabled).
uint16_t ap_pmtu = 0;

// AP SSID hidden (0 = visible, 1 = hidden)
uint8_t ap_ssid_hidden = 0;

#if CONFIG_ETH_UPLINK
// AP WiFi channel (0 = auto, 1-13 = fixed channel; ETH_UPLINK only)
uint8_t ap_channel = 0;
#endif

#if !CONFIG_ETH_UPLINK
// WPA2-Enterprise settings
int32_t eap_method = 0;          // 0=Auto, 1=PEAP, 2=TTLS, 3=TLS
int32_t ttls_phase2 = 0;         // 0=MSCHAPv2, 1=MSCHAP, 2=PAP, 3=CHAP
int32_t use_cert_bundle = 0;     // 0=off, 1=on
int32_t disable_time_check = 0;  // 0=off, 1=on
#endif

// WireGuard VPN settings
int32_t vpn_enabled = 0;
int32_t vpn_port = 51820;
int32_t vpn_keepalive = 0;
char* vpn_private_key = NULL;
char* vpn_public_key = NULL;
char* vpn_preshared_key = NULL;
char* vpn_endpoint = NULL;
char* vpn_address = NULL;
char* vpn_netmask = NULL;
bool vpn_connected = false;
uint32_t vpn_tunnel_ip = 0;         // Cached VPN tunnel IP (network byte order)
int32_t vpn_killswitch = 1;         // Kill switch default on
int32_t vpn_route_all = 1;          // Route all traffic through VPN (default on)

/* FreeRTOS event group to signal when we are connected*/
static EventGroupHandle_t wifi_event_group;

/* The event group allows multiple bits for each event, but we only care about one event
 * - are we connected to the AP with an IP? */
const int WIFI_CONNECTED_BIT = BIT0;

#define DEFAULT_AP_IP "192.168.4.1"
#define DEFAULT_DNS "8.8.8.8"

/* Global vars */
uint16_t connect_count = 0;
bool ap_connect = false;
bool has_static_ip = false;
int led_gpio = -1;  // -1 means LED disabled (none)
uint8_t led_lowactive = 0;  // 0 = active-high (default), 1 = active-low (inverted)
uint8_t led_toggle = 0;  // Shared toggle state for packet-driven LED flicker

uint32_t my_ip;
uint32_t my_ap_ip;

struct portmap_table_entry portmap_tab[IP_PORTMAP_MAX];
struct dhcp_reservation_entry dhcp_reservations[MAX_DHCP_RESERVATIONS];

esp_netif_t* wifiAP;
#if CONFIG_ETH_UPLINK
esp_netif_t* ethNetif = NULL;
esp_eth_handle_t eth_handle = NULL;
#else
esp_netif_t* wifiSTA;
#endif

httpd_handle_t start_webserver(void);

static const char *TAG = "ESP32 NAT router";

/* Console command history can be stored to and loaded from a file.
 * The easiest way to do this is to use FATFS filesystem on top of
 * wear_levelling library.
 */
#if CONFIG_STORE_HISTORY

#define MOUNT_PATH "/data"
#define HISTORY_PATH MOUNT_PATH "/history.txt"

static void initialize_filesystem(void)
{
    static wl_handle_t wl_handle;
    const esp_vfs_fat_mount_config_t mount_config = {
            .max_files = 4,
            .format_if_mount_failed = true
    };
    esp_err_t err = esp_vfs_fat_spiflash_mount_rw_wl(MOUNT_PATH, "storage", &mount_config, &wl_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to mount FATFS (%s)", esp_err_to_name(err));
        return;
    }
}
#endif // CONFIG_STORE_HISTORY

static void initialize_nvs(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK( nvs_flash_erase() );
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);
}

static void initialize_console(void)
{
    /* Disable buffering on stdin */
    setvbuf(stdin, NULL, _IONBF, 0);

#if CONFIG_ESP_CONSOLE_UART_DEFAULT || CONFIG_ESP_CONSOLE_UART_CUSTOM
    /* Drain stdout before reconfiguring it */
    fflush(stdout);
    fsync(fileno(stdout));

    /* Minicom, screen, idf_monitor send CR when ENTER key is pressed */
    uart_vfs_dev_port_set_rx_line_endings(0, ESP_LINE_ENDINGS_CR);
    /* Move the caret to the beginning of the next line on '\n' */
    uart_vfs_dev_port_set_tx_line_endings(0, ESP_LINE_ENDINGS_CRLF);

    /* Configure UART. Note that REF_TICK is used so that the baud rate remains
     * correct while APB frequency is changing in light sleep mode.
     */
    const uart_config_t uart_config = {
            .baud_rate = CONFIG_ESP_CONSOLE_UART_BAUDRATE,
            .data_bits = UART_DATA_8_BITS,
            .parity = UART_PARITY_DISABLE,
            .stop_bits = UART_STOP_BITS_1,
            .source_clk = UART_SCLK_DEFAULT,
    };
    /* Install UART driver for interrupt-driven reads and writes */
    ESP_ERROR_CHECK( uart_driver_install(CONFIG_ESP_CONSOLE_UART_NUM,
            256, 0, 0, NULL, 0) );
    ESP_ERROR_CHECK( uart_param_config(CONFIG_ESP_CONSOLE_UART_NUM, &uart_config) );

    /* Tell VFS to use UART driver */
    uart_vfs_dev_use_driver(CONFIG_ESP_CONSOLE_UART_NUM);
#endif

#if CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG
    /* Enable non-blocking mode on stdin and stdout */
    fcntl(fileno(stdout), F_SETFL, O_NONBLOCK);
    fcntl(fileno(stdin), F_SETFL, O_NONBLOCK);

    /* Minicom, screen, idf_monitor send CR when ENTER key is pressed */
    usb_serial_jtag_vfs_set_rx_line_endings(ESP_LINE_ENDINGS_CR);

    /* Move the caret to the beginning of the next line on '\n' */
    usb_serial_jtag_vfs_set_tx_line_endings(ESP_LINE_ENDINGS_CRLF);
    usb_serial_jtag_driver_config_t usb_serial_jtag_config = {
        .tx_buffer_size = 256,
        .rx_buffer_size = 256,
    };

    /* Install USB-SERIAL-JTAG driver for interrupt-driven reads and writes */
    usb_serial_jtag_driver_install(&usb_serial_jtag_config);

    /* Tell vfs to use usb-serial-jtag driver */
    usb_serial_jtag_vfs_use_driver();
#endif

    /* Initialize the console */
    esp_console_config_t console_config = {
            .max_cmdline_args = 12,
            .max_cmdline_length = 256,
#if CONFIG_LOG_COLORS
            .hint_color = atoi(LOG_COLOR_CYAN)
#endif
    };
    ESP_ERROR_CHECK( esp_console_init(&console_config) );

    /* Configure linenoise line completion library */
    /* Enable multiline editing. If not set, long commands will scroll within
     * single line.
     */
    linenoiseSetMultiLine(1);

    /* Tell linenoise where to get command completions and hints */
    linenoiseSetCompletionCallback(&esp_console_get_completion);
    linenoiseSetHintsCallback((linenoiseHintsCallback*) &esp_console_get_hint);

    /* Set command history size */
    linenoiseHistorySetMaxLen(100);

#if CONFIG_STORE_HISTORY
    /* Load command history from filesystem */
    linenoiseHistoryLoad(HISTORY_PATH);
#endif
}

// BOOT button is GPIO 9 on ESP32-C3/C2/C6, GPIO 0 on ESP32/S2/S3
#if defined(CONFIG_IDF_TARGET_ESP32C3) || defined(CONFIG_IDF_TARGET_ESP32C2) || defined(CONFIG_IDF_TARGET_ESP32C6)
#define BOOT_BUTTON_GPIO      9
#else
#define BOOT_BUTTON_GPIO      0
#endif
#define FACTORY_RESET_HOLD_MS 5000
#define POLL_INTERVAL_MS      50

void * led_status_thread(void * p)
{
#if !CONFIG_ETH_UPLINK
    // Init boot button for factory reset detection (GPIO0 used by ETH clock on WT32-ETH01)
    gpio_reset_pin(BOOT_BUTTON_GPIO);
    gpio_set_direction(BOOT_BUTTON_GPIO, GPIO_MODE_INPUT);
    gpio_set_pull_mode(BOOT_BUTTON_GPIO, GPIO_PULLUP_ONLY);
#endif

    bool led_enabled = (led_gpio >= 0);
    if (led_enabled) {
        ESP_LOGI(TAG, "LED status on GPIO %d%s", led_gpio, led_lowactive ? " (low-active)" : "");
        gpio_reset_pin(led_gpio);
        gpio_set_direction(led_gpio, GPIO_MODE_OUTPUT);
    } else {
        ESP_LOGI(TAG, "LED status disabled (no GPIO configured)");
    }

    int held_ms = 0;

    while (true)
    {
        // --- LED status: OFF=disconnected, ON=connected (packet hooks flicker it off) ---
        if (led_enabled && held_ms == 0) {
            gpio_set_level(led_gpio, ap_connect ^ led_lowactive);
        }

        // --- Poll interval with button polling ---
        for (int t = 0; t < 1000 / POLL_INTERVAL_MS; t++) {
            vTaskDelay(pdMS_TO_TICKS(POLL_INTERVAL_MS));

#if !CONFIG_ETH_UPLINK
            if (gpio_get_level(BOOT_BUTTON_GPIO) == 0) {
                held_ms += POLL_INTERVAL_MS;
                // Rapid LED toggle for visual feedback during hold
                if (led_enabled) {
                    gpio_set_level(led_gpio, ((held_ms / POLL_INTERVAL_MS) % 2) ^ led_lowactive);
                }
                if (held_ms >= FACTORY_RESET_HOLD_MS) {
                    ESP_LOGW(TAG, "BOOT button held %d ms - factory reset!", held_ms);
                    nvs_handle_t nvs;
                    if (nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs) == ESP_OK) {
                        nvs_erase_all(nvs);
                        nvs_commit(nvs);
                        nvs_close(nvs);
                    }
                    esp_restart();
                }
            } else {
                held_ms = 0;
            }
#endif
        }
    }
}

/* Event handlers */

#if CONFIG_ETH_UPLINK
static void eth_event_handler(void* arg, esp_event_base_t event_base,
                               int32_t event_id, void* event_data)
{
    if (event_base == ETH_EVENT) {
        if (event_id == ETHERNET_EVENT_CONNECTED) {
            ESP_LOGI(TAG, "Ethernet link up");
        } else if (event_id == ETHERNET_EVENT_DISCONNECTED) {
            ESP_LOGI(TAG, "Ethernet link down");
            if (vpn_connected) {
                vpn_disconnect();
            }
            ap_connect = false;
            xEventGroupClearBits(wifi_event_group, WIFI_CONNECTED_BIT);
        } else if (event_id == ETHERNET_EVENT_START) {
            ESP_LOGI(TAG, "Ethernet started");
        }
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_ETH_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        ESP_LOGI(TAG, "ETH got ip:" IPSTR, IP2STR(&event->ip_info.ip));
        ap_connect = true;
        my_ip = event->ip_info.ip.addr;
        delete_portmap_tab();
        apply_portmap_tab();

        // Copy DNS from ETH to AP
        esp_netif_dns_info_t dns;
        if (!(ap_dns && ap_dns[0])) {
            if (esp_netif_get_dns_info(ethNetif, ESP_NETIF_DNS_MAIN, &dns) == ESP_OK) {
                esp_netif_set_dns_info(wifiAP, ESP_NETIF_DNS_MAIN, &dns);
                ESP_LOGI(TAG, "set dns to:" IPSTR, IP2STR(&(dns.ip.u_addr.ip4)));
            }
        }

        init_byte_counter();

        init_sntp_if_needed();
        if (vpn_enabled) {
            xTaskCreate(vpn_connect_task, "vpn_connect", 4096, NULL, 5, NULL);
        }
        xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

static void wifi_ap_event_handler(void* arg, esp_event_base_t event_base,
                                   int32_t event_id, void* event_data)
{
    if (event_id == WIFI_EVENT_AP_START) {
        ESP_LOGI(TAG, "AP started");
        init_ap_netif_hooks();
    } else if (event_id == WIFI_EVENT_AP_STACONNECTED) {
        wifi_event_ap_staconnected_t* event = (wifi_event_ap_staconnected_t*) event_data;
        connect_count++;
        const char* name = lookup_device_name_by_mac(event->mac);
        if (name) {
            ESP_LOGI(TAG, "Client connected: %02X:%02X:%02X:%02X:%02X:%02X (%s) - %d total",
                     event->mac[0], event->mac[1], event->mac[2],
                     event->mac[3], event->mac[4], event->mac[5],
                     name, connect_count);
        } else {
            ESP_LOGI(TAG, "Client connected: %02X:%02X:%02X:%02X:%02X:%02X - %d total",
                     event->mac[0], event->mac[1], event->mac[2],
                     event->mac[3], event->mac[4], event->mac[5],
                     connect_count);
        }
    } else if (event_id == WIFI_EVENT_AP_STADISCONNECTED) {
        wifi_event_ap_stadisconnected_t* event = (wifi_event_ap_stadisconnected_t*) event_data;
        connect_count--;
        const char* name = lookup_device_name_by_mac(event->mac);
        if (name) {
            ESP_LOGI(TAG, "Client disconnected: %02X:%02X:%02X:%02X:%02X:%02X (%s) - %d remain",
                     event->mac[0], event->mac[1], event->mac[2],
                     event->mac[3], event->mac[4], event->mac[5],
                     name, connect_count);
        } else {
            ESP_LOGI(TAG, "Client disconnected: %02X:%02X:%02X:%02X:%02X:%02X - %d remain",
                     event->mac[0], event->mac[1], event->mac[2],
                     event->mac[3], event->mac[4], event->mac[5],
                     connect_count);
        }
    }
}
#else
static void wifi_event_handler(void* arg, esp_event_base_t event_base,
                                int32_t event_id, void* event_data)
{
    esp_netif_dns_info_t dns;

    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START)
    {
        esp_wifi_connect();
    }
    else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED)
    {
        ESP_LOGI(TAG,"disconnected - retry to connect to the AP");
        if (vpn_connected) {
            vpn_disconnect();
        }
        ap_connect = false;
        esp_wifi_connect();
        ESP_LOGI(TAG, "retry to connect to the AP");
        xEventGroupClearBits(wifi_event_group, WIFI_CONNECTED_BIT);
    }
    else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP)
    {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        ESP_LOGI(TAG, "got ip:" IPSTR, IP2STR(&event->ip_info.ip));
        ap_connect = true;
        my_ip = event->ip_info.ip.addr;
        delete_portmap_tab();
        apply_portmap_tab();
        if (!(ap_dns && ap_dns[0])) {
            if (esp_netif_get_dns_info(wifiSTA, ESP_NETIF_DNS_MAIN, &dns) == ESP_OK)
            {
                esp_netif_set_dns_info(wifiAP, ESP_NETIF_DNS_MAIN, &dns);
                ESP_LOGI(TAG, "set dns to:" IPSTR, IP2STR(&(dns.ip.u_addr.ip4)));
            }
        }

        // Initialize byte counter after getting IP (interface is ready)
        init_byte_counter();

        // Start SNTP time synchronization
        init_sntp_if_needed();

        // Start VPN connection if enabled
        if (vpn_enabled) {
            xTaskCreate(vpn_connect_task, "vpn_connect", 4096, NULL, 5, NULL);
        }

        xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_BIT);
    }
    else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_START)
    {
        ESP_LOGI(TAG, "AP started");
        // Initialize AP netif hooks now that interface is ready
        init_ap_netif_hooks();
    }
    else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STACONNECTED)
    {
        wifi_event_ap_staconnected_t* event = (wifi_event_ap_staconnected_t*) event_data;
        connect_count++;

        /* Look up device name from DHCP reservations */
        const char* name = lookup_device_name_by_mac(event->mac);
        if (name) {
            ESP_LOGI(TAG, "Client connected: %02X:%02X:%02X:%02X:%02X:%02X (%s) - %d total",
                     event->mac[0], event->mac[1], event->mac[2],
                     event->mac[3], event->mac[4], event->mac[5],
                     name, connect_count);
        } else {
            ESP_LOGI(TAG, "Client connected: %02X:%02X:%02X:%02X:%02X:%02X - %d total",
                     event->mac[0], event->mac[1], event->mac[2],
                     event->mac[3], event->mac[4], event->mac[5],
                     connect_count);
        }
    }
    else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STADISCONNECTED)
    {
        wifi_event_ap_stadisconnected_t* event = (wifi_event_ap_stadisconnected_t*) event_data;
        connect_count--;

        /* Look up device name from DHCP reservations */
        const char* name = lookup_device_name_by_mac(event->mac);
        if (name) {
            ESP_LOGI(TAG, "Client disconnected: %02X:%02X:%02X:%02X:%02X:%02X (%s) - %d remain",
                     event->mac[0], event->mac[1], event->mac[2],
                     event->mac[3], event->mac[4], event->mac[5],
                     name, connect_count);
        } else {
            ESP_LOGI(TAG, "Client disconnected: %02X:%02X:%02X:%02X:%02X:%02X - %d remain",
                     event->mac[0], event->mac[1], event->mac[2],
                     event->mac[3], event->mac[4], event->mac[5],
                     connect_count);
        }
    }
}
#endif

const int CONNECTED_BIT = BIT0;
#define JOIN_TIMEOUT_MS (2000)


#if CONFIG_ETH_UPLINK
void eth_init(const char* static_ip, const char* subnet_mask, const char* gateway_addr,
              const uint8_t* ap_mac, const char* ap_ssid, const char* ap_passwd, const char* ap_ip)
{
    esp_netif_dns_info_t dnsserver;

    wifi_event_group = xEventGroupCreate();

    esp_netif_init();
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    // --- Ethernet uplink ---
    // Power on LAN8720 PHY via GPIO16 before EMAC init (WT32-ETH01)
#if CONFIG_ETH_PHY_POWER_GPIO >= 0
    gpio_config_t phy_power_cfg = {
        .pin_bit_mask = (1ULL << CONFIG_ETH_PHY_POWER_GPIO),
        .mode = GPIO_MODE_OUTPUT,
    };
    gpio_config(&phy_power_cfg);
    gpio_set_level(CONFIG_ETH_PHY_POWER_GPIO, 1);
    vTaskDelay(pdMS_TO_TICKS(20));  // Let PHY power stabilize
#endif

    eth_mac_config_t mac_config = ETH_MAC_DEFAULT_CONFIG();
    eth_esp32_emac_config_t emac_config = ETH_ESP32_EMAC_DEFAULT_CONFIG();
    emac_config.smi_gpio.mdc_num = CONFIG_ETH_MDC_GPIO;
    emac_config.smi_gpio.mdio_num = CONFIG_ETH_MDIO_GPIO;
    esp_eth_mac_t *mac = esp_eth_mac_new_esp32(&emac_config, &mac_config);

    eth_phy_config_t phy_config = ETH_PHY_DEFAULT_CONFIG();
    phy_config.phy_addr = CONFIG_ETH_PHY_ADDR;
    // phy_config.reset_gpio_num = CONFIG_ETH_PHY_POWER_GPIO;
    phy_config.reset_gpio_num = -1;  // Don't use PHY reset - we handle power via GPIO above
    esp_eth_phy_t *phy = esp_eth_phy_new_lan87xx(&phy_config);

    esp_eth_config_t config = ETH_DEFAULT_CONFIG(mac, phy);
    ESP_ERROR_CHECK(esp_eth_driver_install(&config, &eth_handle));

    esp_netif_config_t netif_cfg = ESP_NETIF_DEFAULT_ETH();
    ethNetif = esp_netif_new(&netif_cfg);
    esp_netif_attach(ethNetif, esp_eth_new_netif_glue(eth_handle));

    // Static IP on ETH if configured
    if (strlen(static_ip) > 0 && strlen(subnet_mask) > 0 && strlen(gateway_addr) > 0) {
        has_static_ip = true;
        esp_netif_ip_info_t ipInfo;
        ipInfo.ip.addr = esp_ip4addr_aton(static_ip);
        ipInfo.gw.addr = esp_ip4addr_aton(gateway_addr);
        ipInfo.netmask.addr = esp_ip4addr_aton(subnet_mask);
        esp_netif_dhcpc_stop(ethNetif);
        esp_netif_set_ip_info(ethNetif, &ipInfo);
        apply_portmap_tab();
    }

    // Register ETH events
    ESP_ERROR_CHECK(esp_event_handler_register(ETH_EVENT, ESP_EVENT_ANY_ID, &eth_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_GOT_IP, &eth_event_handler, NULL));

    // --- WiFi AP only ---
    wifiAP = esp_netif_create_default_wifi_ap();

    my_ap_ip = esp_ip4addr_aton(ap_ip);
    esp_netif_ip_info_t ipInfo_ap;
    ipInfo_ap.ip.addr = my_ap_ip;
    ipInfo_ap.gw.addr = my_ap_ip;
    esp_netif_set_ip4_addr(&ipInfo_ap.netmask, 255,255,255,0);
    esp_netif_dhcps_stop(wifiAP);
    esp_netif_set_ip_info(wifiAP, &ipInfo_ap);
    esp_netif_dhcps_start(wifiAP);

    // WiFi AP-only event handler
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_ap_event_handler, NULL));

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    wifi_config_t ap_config = {
        .ap = {
            .channel = ap_channel,
            .authmode = WIFI_AUTH_WPA2_WPA3_PSK,
            .ssid_hidden = ap_ssid_hidden,
            .max_connection = AP_MAX_CONNECTIONS,
            .beacon_interval = 100,
        }
    };
    strlcpy((char*)ap_config.ap.ssid, ap_ssid, sizeof(ap_config.ap.ssid));
    if (strlen(ap_passwd) < 8) {
        ap_config.ap.authmode = WIFI_AUTH_OPEN;
    } else {
        strlcpy((char*)ap_config.ap.password, ap_passwd, sizeof(ap_config.ap.password));
    }

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_AP, &ap_config));
    if (ap_mac != NULL) {
        ESP_ERROR_CHECK(esp_wifi_set_mac(ESP_IF_WIFI_AP, ap_mac));
    }

    // Enable DNS (offer) for dhcp server
    dhcps_offer_t dhcps_dns_value = OFFER_DNS;
    esp_netif_dhcps_option(wifiAP, ESP_NETIF_OP_SET, ESP_NETIF_DOMAIN_NAME_SERVER, &dhcps_dns_value, sizeof(dhcps_dns_value));

    // DNS server for DHCP clients
    const char *dns_src = (ap_dns && ap_dns[0]) ? ap_dns : "1.1.1.1";
    dnsserver.ip.u_addr.ip4.addr = esp_ip4addr_aton(dns_src);
    dnsserver.ip.type = ESP_IPADDR_TYPE_V4;
    esp_netif_set_dns_info(wifiAP, ESP_NETIF_DNS_MAIN, &dnsserver);

    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_eth_start(eth_handle));

    ESP_LOGI(TAG, "Ethernet-to-WiFi NAT Router initialized");
}
#else
void wifi_init(const uint8_t* mac, const char* ssid, const char* ent_username, const char* ent_identity, const char* passwd, const char* static_ip, const char* subnet_mask, const char* gateway_addr, const uint8_t* ap_mac, const char* ap_ssid, const char* ap_passwd, const char* ap_ip)
{
    esp_netif_dns_info_t dnsserver;
    // esp_netif_dns_info_t dnsinfo;

    wifi_event_group = xEventGroupCreate();

    esp_netif_init();
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    wifiAP = esp_netif_create_default_wifi_ap();
    wifiSTA = esp_netif_create_default_wifi_sta();

    esp_netif_ip_info_t ipInfo_sta;
    if ((strlen(ssid) > 0) && (strlen(static_ip) > 0) && (strlen(subnet_mask) > 0) && (strlen(gateway_addr) > 0)) {
        has_static_ip = true;
        ipInfo_sta.ip.addr = esp_ip4addr_aton(static_ip);
        ipInfo_sta.gw.addr = esp_ip4addr_aton(gateway_addr);
        ipInfo_sta.netmask.addr = esp_ip4addr_aton(subnet_mask);
        esp_netif_dhcpc_stop(wifiSTA); // Don't run a DHCP client
        esp_netif_set_ip_info(wifiSTA, &ipInfo_sta);
        apply_portmap_tab();
    }

    my_ap_ip = esp_ip4addr_aton(ap_ip);

    esp_netif_ip_info_t ipInfo_ap;
    ipInfo_ap.ip.addr = my_ap_ip;
    ipInfo_ap.gw.addr = my_ap_ip;
    esp_netif_set_ip4_addr(&ipInfo_ap.netmask, 255,255,255,0);
    esp_netif_dhcps_stop(wifiAP); // stop before setting ip WifiAP
    esp_netif_set_ip_info(wifiAP, &ipInfo_ap);
    esp_netif_dhcps_start(wifiAP);

    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &wifi_event_handler,
                                                        NULL,
                                                        &instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                                                        IP_EVENT_STA_GOT_IP,
                                                        &wifi_event_handler,
                                                        NULL,
                                                        &instance_got_ip));

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    /* ESP WIFI CONFIG */
    wifi_config_t wifi_config = { 0 };
        wifi_config_t ap_config = {
        .ap = {
            .channel = 0,
            .authmode = WIFI_AUTH_WPA2_WPA3_PSK,
            .ssid_hidden = ap_ssid_hidden,
            .max_connection = AP_MAX_CONNECTIONS,
            .beacon_interval = 100,
        }
    };

    strlcpy((char*)ap_config.sta.ssid, ap_ssid, sizeof(ap_config.sta.ssid));
    if (strlen(ap_passwd) < 8) {
        ap_config.ap.authmode = WIFI_AUTH_OPEN;
    } else {
	    strlcpy((char*)ap_config.sta.password, ap_passwd, sizeof(ap_config.sta.password));
    }

    // Always use APSTA mode so WiFi scanning works even without an uplink configured
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA) );

    if (strlen(ssid) > 0) {
        //Set SSID
        strlcpy((char*)wifi_config.sta.ssid, ssid, sizeof(wifi_config.sta.ssid));
        //Set password
        if(strlen(ent_username) == 0) {
            ESP_LOGI(TAG, "STA regular connection");
            strlcpy((char*)wifi_config.sta.password, passwd, sizeof(wifi_config.sta.password));
        }
        ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config) );
        if(strlen(ent_username) != 0) {
            ESP_LOGI(TAG, "STA enterprise connection");
            if(strlen(ent_identity) != 0) {
                esp_eap_client_set_identity((uint8_t *)ent_identity, strlen(ent_identity));
            } else {
                esp_eap_client_set_identity((uint8_t *)ent_username, strlen(ent_username));
            }
            esp_eap_client_set_username((uint8_t *)ent_username, strlen(ent_username));
            esp_eap_client_set_password((uint8_t *)passwd, strlen(passwd));

            // Set TTLS phase 2 method
            if (ttls_phase2 >= 0 && ttls_phase2 <= 3) {
                esp_eap_client_set_ttls_phase2_method(ttls_phase2);
            }

            // Use CA certificate bundle for server validation
#ifdef CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
            if (use_cert_bundle) {
                esp_eap_client_use_default_cert_bundle(true);
            }
#endif

            // Disable certificate time check
            if (disable_time_check) {
                esp_eap_client_set_disable_time_check(true);
            }

            esp_wifi_sta_enterprise_enable();
        }

        if (mac != NULL) {
            ESP_ERROR_CHECK(esp_wifi_set_mac(ESP_IF_WIFI_STA, mac));
        }
    }

    ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_AP, &ap_config) );

    if (ap_mac != NULL) {
        ESP_ERROR_CHECK(esp_wifi_set_mac(ESP_IF_WIFI_AP, ap_mac));
    }


    // Enable DNS (offer) for dhcp server
    dhcps_offer_t dhcps_dns_value = OFFER_DNS;
    esp_netif_dhcps_option(wifiAP,ESP_NETIF_OP_SET, ESP_NETIF_DOMAIN_NAME_SERVER, &dhcps_dns_value, sizeof(dhcps_dns_value));

    // Set DNS server address for DHCP clients.
    // When no STA is configured, point clients at the AP itself so the
    // captive-portal DNS server can intercept all queries.
    if (strlen(ssid) > 0) {
        const char *dns_src = (ap_dns && ap_dns[0]) ? ap_dns : "1.1.1.1";
        dnsserver.ip.u_addr.ip4.addr = esp_ip4addr_aton(dns_src);
    } else {
        dnsserver.ip.u_addr.ip4.addr = esp_ip4addr_aton(DEFAULT_AP_IP);
    }
    dnsserver.ip.type = ESP_IPADDR_TYPE_V4;
    esp_netif_set_dns_info(wifiAP, ESP_NETIF_DNS_MAIN, &dnsserver);

    // esp_netif_get_dns_info(ESP_IF_WIFI_AP, ESP_NETIF_DNS_MAIN, &dnsinfo);
    // ESP_LOGI(TAG, "DNS IP:" IPSTR, IP2STR(&dnsinfo.ip.u_addr.ip4));

    xEventGroupWaitBits(wifi_event_group, CONNECTED_BIT,
        pdFALSE, pdTRUE, pdMS_TO_TICKS(JOIN_TIMEOUT_MS));
    ESP_ERROR_CHECK(esp_wifi_start());

    if (strlen(ssid) > 0) {
        ESP_LOGI(TAG, "wifi_init_apsta finished.");
        ESP_LOGI(TAG, "connect to ap SSID: %s ", ssid);
    } else {
        ESP_LOGI(TAG, "wifi_init_ap with default finished.");
    }
}
#endif

#if !CONFIG_ETH_UPLINK
uint8_t* mac = NULL;
char* ssid = NULL;
char* ent_username = NULL;
char* ent_identity = NULL;
char* passwd = NULL;
#endif
char* static_ip = NULL;
char* subnet_mask = NULL;
char* gateway_addr = NULL;
uint8_t* ap_mac = NULL;
char* ap_ssid = NULL;
char* ap_passwd = NULL;
char* ap_ip = NULL;
char* ap_dns = NULL;

char* param_set_default(const char* def_val) {
    char * retval = malloc(strlen(def_val)+1);
    if (retval == NULL) {
        ESP_LOGE(TAG, "Failed to allocate memory for default parameter");
        return NULL;
    }
    strcpy(retval, def_val);
    return retval;
}

void app_main(void)
{
    initialize_nvs();
    load_log_level();  // Apply saved log level early

#if CONFIG_STORE_HISTORY
    initialize_filesystem();
    ESP_LOGI(TAG, "Command history enabled");
#else
    ESP_LOGI(TAG, "Command history disabled");
#endif

#if !CONFIG_ETH_UPLINK
    get_config_param_blob("mac", &mac, 6);
    get_config_param_str("ssid", &ssid);
    if (ssid == NULL) {
        ssid = param_set_default("");
    }
    get_config_param_str("ent_username", &ent_username);
    if (ent_username == NULL) {
        ent_username = param_set_default("");
    }
    get_config_param_str("ent_identity", &ent_identity);
    if (ent_identity == NULL) {
        ent_identity = param_set_default("");
    }
    get_config_param_str("passwd", &passwd);
    if (passwd == NULL) {
        passwd = param_set_default("");
    }
#endif
    get_config_param_str("static_ip", &static_ip);
    if (static_ip == NULL) {
        static_ip = param_set_default("");
    }
    get_config_param_str("subnet_mask", &subnet_mask);
    if (subnet_mask == NULL) {
        subnet_mask = param_set_default("");
    }
    get_config_param_str("gateway_addr", &gateway_addr);
    if (gateway_addr == NULL) {
        gateway_addr = param_set_default("");
    }
    get_config_param_blob("ap_mac", &ap_mac, 6);
    get_config_param_str("ap_ssid", &ap_ssid);
    if (ap_ssid == NULL) {
        ap_ssid = param_set_default("ESP32_NAT_Router");
    }
    get_config_param_str("ap_passwd", &ap_passwd);
    if (ap_passwd == NULL) {
        ap_passwd = param_set_default("");
    }
    get_config_param_str("ap_ip", &ap_ip);
    if (ap_ip == NULL) {
        ap_ip = param_set_default(DEFAULT_AP_IP);
    }
    get_config_param_str("ap_dns", &ap_dns);
    if (ap_dns == NULL) {
        ap_dns = param_set_default("");
    }

    get_portmap_tab();
    get_dhcp_reservations();
    load_acl_rules();

    // Load LED GPIO setting from NVS (default -1 = disabled)
    int led_gpio_setting = -1;
    if (get_config_param_int("led_gpio", &led_gpio_setting) == ESP_OK) {
        led_gpio = led_gpio_setting;
    }
    // led_gpio remains -1 (disabled) if not set in NVS

    // Load LED low-active setting from NVS (default 0 = active-high)
    int led_lowactive_setting = 0;
    if (get_config_param_int("led_low", &led_lowactive_setting) == ESP_OK) {
        led_lowactive = (led_lowactive_setting != 0) ? 1 : 0;
    }
    if (led_lowactive) {
        ESP_LOGI(TAG, "LED low-active mode enabled");
    }

    // Load TTL override setting from NVS (default 0 = disabled)
    int ttl_setting = 0;
    if (get_config_param_int("sta_ttl", &ttl_setting) == ESP_OK) {
        if (ttl_setting >= 0 && ttl_setting <= 255) {
            sta_ttl_override = (uint8_t)ttl_setting;
        }
    }
    if (sta_ttl_override > 0) {
        ESP_LOGI(TAG, "TTL override enabled: %d", sta_ttl_override);
    }

    // Load AP SSID hidden setting from NVS (default 0 = visible)
    int hidden_setting = 0;
    if (get_config_param_int("ap_hidden", &hidden_setting) == ESP_OK) {
        ap_ssid_hidden = (hidden_setting != 0) ? 1 : 0;
    }
    if (ap_ssid_hidden) {
        ESP_LOGI(TAG, "AP SSID hidden enabled");
    }

#if CONFIG_ETH_UPLINK
    // Load AP channel setting from NVS (default 0 = auto)
    int channel_setting = 0;
    if (get_config_param_int("ap_channel", &channel_setting) == ESP_OK) {
        if (channel_setting >= 1 && channel_setting <= 13) ap_channel = (uint8_t)channel_setting;
    }
    if (ap_channel > 0) {
        ESP_LOGI(TAG, "AP WiFi channel: %d", ap_channel);
    }
#endif

#if !CONFIG_ETH_UPLINK
    // Load WPA2-Enterprise settings from NVS (defaults: 0)
    int eap_setting = 0;
    if (get_config_param_int("eap_method", &eap_setting) == ESP_OK) {
        eap_method = (int32_t)eap_setting;
    }
    int phase2_setting = 0;
    if (get_config_param_int("ttls_phase2", &phase2_setting) == ESP_OK) {
        ttls_phase2 = (int32_t)phase2_setting;
    }
    int cert_bundle_setting = 0;
    if (get_config_param_int("cert_bundle", &cert_bundle_setting) == ESP_OK) {
        use_cert_bundle = (int32_t)cert_bundle_setting;
    }
    int time_check_setting = 0;
    if (get_config_param_int("no_time_chk", &time_check_setting) == ESP_OK) {
        disable_time_check = (int32_t)time_check_setting;
    }
#endif

    // Load WireGuard VPN settings from NVS
    int vpn_setting = 0;
    if (get_config_param_int("vpn_enabled", &vpn_setting) == ESP_OK) {
        vpn_enabled = (int32_t)vpn_setting;
    }
    get_config_param_str("vpn_privkey", &vpn_private_key);
    if (vpn_private_key == NULL) vpn_private_key = param_set_default("");
    get_config_param_str("vpn_pubkey", &vpn_public_key);
    if (vpn_public_key == NULL) vpn_public_key = param_set_default("");
    get_config_param_str("vpn_psk", &vpn_preshared_key);
    if (vpn_preshared_key == NULL) vpn_preshared_key = param_set_default("");
    get_config_param_str("vpn_endpoint", &vpn_endpoint);
    if (vpn_endpoint == NULL) vpn_endpoint = param_set_default("");
    int vpn_port_setting = 51820;
    if (get_config_param_int("vpn_port", &vpn_port_setting) == ESP_OK) {
        vpn_port = (int32_t)vpn_port_setting;
    }
    get_config_param_str("vpn_ip", &vpn_address);
    if (vpn_address == NULL) vpn_address = param_set_default("");
    get_config_param_str("vpn_mask", &vpn_netmask);
    if (vpn_netmask == NULL) vpn_netmask = param_set_default("255.255.255.0");
    int vpn_ka_setting = 0;
    if (get_config_param_int("vpn_ka", &vpn_ka_setting) == ESP_OK) {
        vpn_keepalive = (int32_t)vpn_ka_setting;
    }
    int vpn_ks_setting = 1;  // Default on
    if (get_config_param_int("vpn_ks", &vpn_ks_setting) == ESP_OK) {
        vpn_killswitch = (int32_t)vpn_ks_setting;
    }
    int vpn_rall_setting = 1;  // Default: route all through VPN
    if (get_config_param_int("vpn_rall", &vpn_rall_setting) == ESP_OK) {
        vpn_route_all = (int32_t)vpn_rall_setting;
    }
    // Cache VPN subnet for kill switch packet filtering
    if (vpn_address && vpn_address[0]) {
        ip_addr_t addr, mask;
        if (ipaddr_aton(vpn_address, &addr) && ipaddr_aton(
                (vpn_netmask && vpn_netmask[0]) ? vpn_netmask : "255.255.255.0", &mask)) {
            vpn_set_subnet(ip_2_ip4(&addr)->addr & ip_2_ip4(&mask)->addr,
                           ip_2_ip4(&mask)->addr);
        }
    }
    // Pre-set MSS/PMTU when VPN is enabled (before WiFi connects)
    if (vpn_enabled) {
        ap_mss_clamp = 1380;
        ap_pmtu = 1440;
        ESP_LOGI(TAG, "VPN enabled, MSS=1380 PMTU=1440 pre-set");
    }

#if CONFIG_ETH_UPLINK
    eth_init(static_ip, subnet_mask, gateway_addr, ap_mac, ap_ssid, ap_passwd, ap_ip);
#else
    wifi_init(mac, ssid, ent_username, ent_identity, passwd, static_ip, subnet_mask, gateway_addr, ap_mac, ap_ssid, ap_passwd, ap_ip);
#endif

    pthread_t t1;
    pthread_create(&t1, NULL, led_status_thread, NULL);

    ip_napt_enable(my_ap_ip, 1);
    ESP_LOGI(TAG, "NAT is enabled");

    char* web_disabled = NULL;
    get_config_param_str("lock", &web_disabled);
    if (web_disabled == NULL) {
        web_disabled = param_set_default("0");
    }
    if (strcmp(web_disabled, "0") ==0) {
        ESP_LOGI(TAG,"Starting web server");
        start_webserver();
    }
    free(web_disabled);

    // Initialize PCAP capture (TCP server on port 19000)
    pcap_init();

    // Initialize remote console (TCP server on port 2323, disabled by default)
    remote_console_init();

    // Initialize OLED display (disabled by default, enable via 'set_oled enable')
    oled_display_init();

    initialize_console();

    /* Register commands */
    esp_console_register_help_command();
    register_system();
    register_router();

    /* Prompt to be printed before each line.
     * This can be customized, made dynamic, etc.
     */
    const char* prompt = LOG_COLOR_I "esp32> " LOG_RESET_COLOR;

    printf("\n"
           "ESP32 NAT ROUTER\n"
           "Type 'help' to get the list of commands.\n"
           "Use UP/DOWN arrows to navigate through command history.\n"
           "Press TAB when typing command name to auto-complete.\n");

#if CONFIG_ETH_UPLINK
    printf("\nESP32 Ethernet-to-WiFi NAT Router\n"
           "Configure AP using 'set_ap' and restart.\n");
#else
    if (strlen(ssid) == 0) {
         printf("\n"
               "Unconfigured WiFi\n"
               "Configure using 'set_sta' and 'set_ap' and restart.\n");
    }
#endif

    /* Figure out if the terminal supports escape sequences */
    int probe_status = linenoiseProbe();
    if (probe_status) { /* zero indicates success */
        printf("\n"
               "Your terminal application does not support escape sequences.\n"
               "Line editing and history features are disabled.\n"
               "On Windows, try using Putty instead.\n");
        linenoiseSetDumbMode(1);
#if CONFIG_LOG_COLORS
        /* Since the terminal doesn't support escape sequences,
         * don't use color codes in the prompt.
         */
        prompt = "esp32> ";
#endif //CONFIG_LOG_COLORS
    }

    /* Main loop */
    while(true) {
        /* Get a line using linenoise.
         * The line is returned when ENTER is pressed.
         */
        char* line = linenoise(prompt);
        if (line == NULL) { /* Ignore empty lines */
            continue;
        }
        /* Add the command to the history */
        linenoiseHistoryAdd(line);
#if CONFIG_STORE_HISTORY
        /* Save command history to filesystem */
        linenoiseHistorySave(HISTORY_PATH);
#endif

        /* Try to run the command */
        int ret;
        esp_err_t err = esp_console_run(line, &ret);
        if (err == ESP_ERR_NOT_FOUND) {
            printf("Unrecognized command\n");
        } else if (err == ESP_ERR_INVALID_ARG) {
            // command was empty
        } else if (err == ESP_OK && ret != ESP_OK) {
            printf("Command returned non-zero error code: 0x%x (%s)\n", ret, esp_err_to_name(ret));
        } else if (err != ESP_OK) {
            printf("Internal error: %s\n", esp_err_to_name(err));
        }
        /* linenoise allocates line buffer on the heap, so need to free it */
        linenoiseFree(line);
    }
}
