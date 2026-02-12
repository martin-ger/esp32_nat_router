if(IDF_TARGET STREQUAL "esp32c3")
    set(OLED_SRCS "oled_display.c")
    set(OLED_REQUIRES esp_driver_i2c nvs_flash freertos log lwip esp_netif esp_wifi)
else()
    set(OLED_SRCS "")
    set(OLED_REQUIRES "")
endif()

idf_component_register(
    SRCS ${OLED_SRCS}
    INCLUDE_DIRS "include"
    REQUIRES ${OLED_REQUIRES}
)
