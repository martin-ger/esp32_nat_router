set(main_priv_requires
    pcap_capture esp_wifi esp_netif console nvs_flash driver esp_http_server
    fatfs cmd_router dhcpserver wpa_supplicant cmd_system acl remote_console
    syslog oled_display json esp_wireguard esp_eth http_server mqtt_ha app_update)

# ESP32-C5 uses a bit-bang WS2812 driver; all other targets use the RMT-backed
# espressif/led_strip managed component.
if(NOT IDF_TARGET STREQUAL "esp32c5")
    list(APPEND main_priv_requires led_strip)
endif()

idf_component_register(SRCS "esp32_nat_router.c"
                            "portmap.c"
                            "dhcp_manager.c"
                            "vpn_manager.c"
                            "netif_hooks.c"
                            "led_strip_status.c"
                    INCLUDE_DIRS "."
                    PRIV_REQUIRES ${main_priv_requires})
