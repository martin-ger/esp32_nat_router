# ACL (Access Control List) Firewall Component
#
# Provides packet filtering for the ESP32 NAT Router.

idf_component_register(
    SRCS "acl.c"
    INCLUDE_DIRS "include"
    REQUIRES lwip esp_netif esp_timer
)
