/* Console example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#include <stdio.h>
#include <string.h>
#include "esp_system.h"
#include "esp_log.h"
#include "esp_console.h"
#include "esp_vfs_dev.h"
#include "driver/uart.h"
#include "linenoise/linenoise.h"
#include "argtable3/argtable3.h"
#include "esp_vfs_fat.h"
#include "nvs.h"
#include "nvs_flash.h"

#include "freertos/event_groups.h"
#include "esp_wifi.h"

#include "lwip/opt.h"
#include "lwip/err.h"
#include "lwip/sys.h"

#include "cmd_decl.h"
#include "router_globals.h"
#include <esp_http_server.h>

#if IP_NAPT
#include "lwip/lwip_napt.h"
#endif

#include "esp32_nat_router.h"

/* FreeRTOS event group to signal when we are connected*/
static EventGroupHandle_t wifi_event_group;

/* The event group allows multiple bits for each event, but we only care about one event
 * - are we connected to the AP with an IP? */
const int WIFI_CONNECTED_BIT = BIT0;

#define MY_DNS_IP_ADDR 0x08080808 // 8.8.8.8

uint16_t connect_count = 0;
bool ap_connect = false;

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
    esp_err_t err = esp_vfs_fat_spiflash_mount(MOUNT_PATH, "storage", &mount_config, &wl_handle);
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
    /* Drain stdout before reconfiguring it */
    fflush(stdout);
    fsync(fileno(stdout));

    /* Disable buffering on stdin */
    setvbuf(stdin, NULL, _IONBF, 0);

    /* Minicom, screen, idf_monitor send CR when ENTER key is pressed */
    esp_vfs_dev_uart_set_rx_line_endings(ESP_LINE_ENDINGS_CR);
    /* Move the caret to the beginning of the next line on '\n' */
    esp_vfs_dev_uart_set_tx_line_endings(ESP_LINE_ENDINGS_CRLF);

    /* Configure UART. Note that REF_TICK is used so that the baud rate remains
     * correct while APB frequency is changing in light sleep mode.
     */
    const uart_config_t uart_config = {
            .baud_rate = CONFIG_ESP_CONSOLE_UART_BAUDRATE,
            .data_bits = UART_DATA_8_BITS,
            .parity = UART_PARITY_DISABLE,
            .stop_bits = UART_STOP_BITS_1,
            .source_clk = UART_SCLK_REF_TICK,
    };
    /* Install UART driver for interrupt-driven reads and writes */
    ESP_ERROR_CHECK( uart_driver_install(CONFIG_ESP_CONSOLE_UART_NUM,
            256, 0, 0, NULL, 0) );
    ESP_ERROR_CHECK( uart_param_config(CONFIG_ESP_CONSOLE_UART_NUM, &uart_config) );

    /* Tell VFS to use UART driver */
    esp_vfs_dev_uart_use_driver(CONFIG_ESP_CONSOLE_UART_NUM);

    /* Initialize the console */
    esp_console_config_t console_config = {
            .max_cmdline_args = 8,
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

static esp_err_t wifi_event_handler(void *ctx, system_event_t *event)
{
  switch(event->event_id) {
    case SYSTEM_EVENT_STA_START:
        esp_wifi_connect();
        break;
    case SYSTEM_EVENT_STA_GOT_IP:
        ap_connect = true;
        ESP_LOGI(TAG, "got ip:" IPSTR, IP2STR(&event->event_info.got_ip.ip_info.ip));
        xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_BIT);
        break;
    case SYSTEM_EVENT_STA_DISCONNECTED:
        ESP_LOGI(TAG,"disconnected - retry to connect to the AP");
        ap_connect = false;
        esp_wifi_connect();
        xEventGroupClearBits(wifi_event_group, WIFI_CONNECTED_BIT);
        break;
    case SYSTEM_EVENT_AP_STACONNECTED:
        connect_count++;
        ESP_LOGI(TAG,"%d. station connected", connect_count);
        break;
    case SYSTEM_EVENT_AP_STADISCONNECTED:
        connect_count--;
        ESP_LOGI(TAG,"station disconnected - %d remain", connect_count);
        break;
    default:
        break;
  }
  return ESP_OK;
}

const int CONNECTED_BIT = BIT0;
#define JOIN_TIMEOUT_MS (2000)

void wifi_init(const char* ssid, const char* passwd, const char* ap_ssid, const char* ap_passwd)
{
    ip_addr_t dnsserver;
    //tcpip_adapter_dns_info_t dnsinfo;

    wifi_event_group = xEventGroupCreate();
  
    esp_netif_init();
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_t* wifiAP = esp_netif_create_default_wifi_ap();
    esp_netif_t* wifiSTA = esp_netif_create_default_wifi_sta();

    esp_netif_ip_info_t ipInfo;

    IP4_ADDR(&ipInfo.ip, 192,168,4,1);
	IP4_ADDR(&ipInfo.gw, 192,168,4,1);
	IP4_ADDR(&ipInfo.netmask, 255,255,255,0);
	esp_netif_set_ip_info(wifiAP, &ipInfo);
   
    ESP_ERROR_CHECK(esp_event_loop_init(wifi_event_handler, NULL) );

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    /* ESP WIFI CONFIG */
    wifi_config_t wifi_config = { 0 };
        wifi_config_t ap_config = {
        .ap = {
            .channel = 0,
            .authmode = WIFI_AUTH_WPA2_PSK,
            .ssid_hidden = 0,
            .max_connection = 8,
            .beacon_interval = 100,
        }
    };

    strlcpy((char*)ap_config.sta.ssid, ap_ssid, sizeof(ap_config.sta.ssid));
    if (strlen(ap_passwd) < 8) {
        ap_config.ap.authmode = WIFI_AUTH_OPEN;
    } else {
	    strlcpy((char*)ap_config.sta.password, ap_passwd, sizeof(ap_config.sta.password));
    }

    if (strlen(ssid) > 0) {
        strlcpy((char*)wifi_config.sta.ssid, ssid, sizeof(wifi_config.sta.ssid));
        strlcpy((char*)wifi_config.sta.password, passwd, sizeof(wifi_config.sta.password));
        ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA) );
        ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config) );
        ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_AP, &ap_config) );
    } else {
        ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP) );
        ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_AP, &ap_config) );        
    }

    // Enable DNS (offer) for dhcp server
    dhcps_offer_t dhcps_dns_value = OFFER_DNS;
    dhcps_set_option_info(6, &dhcps_dns_value, sizeof(dhcps_dns_value));

    // Set custom dns server address for dhcp server
    dnsserver.u_addr.ip4.addr = htonl(MY_DNS_IP_ADDR);
    dnsserver.type = IPADDR_TYPE_V4;
    dhcps_dns_setserver(&dnsserver);

//    tcpip_adapter_get_dns_info(TCPIP_ADAPTER_IF_AP, TCPIP_ADAPTER_DNS_MAIN, &dnsinfo);
//    ESP_LOGI(TAG, "DNS IP:" IPSTR, IP2STR(&dnsinfo.ip.u_addr.ip4));

    xEventGroupWaitBits(wifi_event_group, CONNECTED_BIT,
        pdFALSE, pdTRUE, JOIN_TIMEOUT_MS / portTICK_PERIOD_MS);
    ESP_ERROR_CHECK(esp_wifi_start());

    if (strlen(ssid) > 0) {
        ESP_LOGI(TAG, "wifi_init_apsta finished.");
        ESP_LOGI(TAG, "connect to ap SSID: %s ", ssid);
    } else {
        ESP_LOGI(TAG, "wifi_init_ap with default finished.");      
    }
}

char* ssid = NULL;
char* passwd = NULL;
char* ap_ssid = NULL;
char* ap_passwd = NULL;

char* param_set_default(const char* def_val) {
    char * retval = malloc(strlen(def_val)+1);
    strcpy(retval, def_val);
    return retval;
}

void app_main(void)
{
    initialize_nvs();

#if CONFIG_STORE_HISTORY
    initialize_filesystem();
    ESP_LOGI(TAG, "Command history enabled");
#else
    ESP_LOGI(TAG, "Command history disabled");
#endif

    get_config_param_str("ssid", &ssid);
    if (ssid == NULL) {
        ssid = param_set_default("");
    }
    get_config_param_str("passwd", &passwd);
    if (passwd == NULL) {
        passwd = param_set_default("");
    }
    get_config_param_str("ap_ssid", &ap_ssid);
    if (ap_ssid == NULL) {
        ap_ssid = param_set_default("ESP32_NAT_Router");
    }   
    get_config_param_str("ap_passwd", &ap_passwd);
    if (ap_passwd == NULL) {
        ap_passwd = param_set_default("");
    }
    // Setup WIFI
    wifi_init(ssid, passwd, ap_ssid, ap_passwd);

#if IP_NAPT
    u32_t napt_netif_ip = 0xC0A80401; // Set to ip address of softAP netif (Default is 192.168.4.1)
    ip_napt_enable(htonl(napt_netif_ip), 1);
    ESP_LOGI(TAG, "NAT is enabled");
#endif

    char* lock = NULL;
    get_config_param_str("lock", &lock);
    if (lock == NULL) {
        lock = param_set_default("0");
    }
    if (strcmp(lock, "0") ==0) {
        ESP_LOGI(TAG,"Starting config web server");
        start_webserver();
    }
    free(lock);

    initialize_console();

    /* Register commands */
    esp_console_register_help_command();
    register_system();
    register_nvs();
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

    if (strlen(ssid) == 0) {
         printf("\n"
               "Unconfigured WiFi\n"
               "Configure using 'set_sta' and 'set_ap' and restart.\n");       
    }

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
