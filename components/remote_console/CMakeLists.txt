idf_component_register(
    SRCS "remote_console.c"
    INCLUDE_DIRS "include"
    REQUIRES esp_timer nvs_flash console lwip esp_netif esp_event log
)

# Wrap output functions to intercept console output
# Note: Do NOT wrap vprintf - it's used by ESP_LOG internally
target_link_libraries(${COMPONENT_LIB} INTERFACE
    "-Wl,--wrap=printf"
    "-Wl,--wrap=puts"
    "-Wl,--wrap=putchar"
    "-Wl,--wrap=fputs"
    "-Wl,--wrap=fwrite"
)
