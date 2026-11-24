if(CONFIG_GPIO_MONITOR)
    set(GPIO_MON_SRCS "gpio_monitor.c" "gpio_monitor_nvs.c")
else()
    set(GPIO_MON_SRCS "")
endif()

idf_component_register(
    SRCS ${GPIO_MON_SRCS}
    INCLUDE_DIRS "include" "${CMAKE_SOURCE_DIR}/include"
    REQUIRES esp_driver_gpio esp_adc esp_timer nvs_flash freertos log
    PRIV_REQUIRES cmd_router oled_display
)
if(GPIO_MON_SRCS)
    target_compile_options(${COMPONENT_LIB} PRIVATE -Os)
endif()