idf_component_register(SRCS "esp32_nat_router.c"
                            "http_server.c"
                    INCLUDE_DIRS "."
                    PRIV_REQUIRES pcap_capture esp_wifi esp_netif console nvs_flash driver esp_http_server fatfs cmd_router dhcpserver wpa_supplicant cmd_system acl remote_console oled_display)

set_source_files_properties(http_server.c
    PROPERTIES COMPILE_FLAGS
    -Wno-unused-function
)
