if(CONFIG_MQTT_HOMEASSISTANT)
    set(MQTT_HA_SRCS "mqtt_ha.c")
else()
    set(MQTT_HA_SRCS "")
endif()

idf_component_register(
    SRCS ${MQTT_HA_SRCS}
    INCLUDE_DIRS "include"
    PRIV_REQUIRES mqtt esp_event esp_wifi esp_netif esp_timer nvs_flash console cmd_router remote_console
)
