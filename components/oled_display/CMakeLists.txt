idf_component_register(
    SRCS "oled_display.c"
    INCLUDE_DIRS "include"
    REQUIRES esp_driver_i2c nvs_flash freertos log lwip esp_netif
)
