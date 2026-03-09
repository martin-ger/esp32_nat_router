idf_component_register(
    SRCS "syslog_client.c"
    INCLUDE_DIRS "include" "${CMAKE_SOURCE_DIR}/include"
    REQUIRES lwip nvs_flash log esp_netif
)
