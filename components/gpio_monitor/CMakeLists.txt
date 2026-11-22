idf_component_register(
    SRCS "gpio_monitor.c" "gpio_monitor_nvs.c"
    INCLUDE_DIRS "include" "${CMAKE_SOURCE_DIR}/include"
    REQUIRES esp_driver_gpio esp_adc esp_timer nvs_flash freertos log
    PRIV_REQUIRES cmd_router
)
target_compile_options(${COMPONENT_LIB} PRIVATE -Os)