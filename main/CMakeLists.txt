idf_component_register(SRCS "esp32_nat_router.c"
                            "portmap.c"
                            "dhcp_manager.c"
                            "vpn_manager.c"
                            "netif_hooks.c"
                    INCLUDE_DIRS "."
                    PRIV_REQUIRES pcap_capture esp_wifi esp_netif console nvs_flash driver esp_http_server fatfs cmd_router dhcpserver wpa_supplicant cmd_system acl remote_console oled_display json esp_wireguard esp_eth http_server)
