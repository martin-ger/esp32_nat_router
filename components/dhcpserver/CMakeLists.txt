# Custom DHCP Server Component
# This component provides a custom DHCP server implementation that wraps
# the built-in ESP-IDF dhcpserver functions using linker --wrap.
#
# The approach:
# - CONFIG_LWIP_DHCPS remains enabled (keeps all config options working)
# - We use linker wrapping to intercept all dhcpserver function calls
# - Our implementation completely replaces the original
# - Original functions are available via __real_* if needed

idf_component_register(
    SRCS "dhcpserver.c"
    INCLUDE_DIRS "include"
    REQUIRES lwip
    PRIV_REQUIRES cmd_router
)

# Suppress address comparison warnings (same as upstream lwip component)
# Suppress unused-but-set-variable for ESP_LOG macros that may be compiled out
target_compile_options(${COMPONENT_LIB} PRIVATE -Wno-address -Wno-unused-but-set-variable)

# List of all public dhcpserver functions to wrap
set(DHCPS_WRAP_FUNCTIONS
    dhcps_new
    dhcps_delete
    dhcps_start
    dhcps_stop
    dhcps_option_info
    dhcps_set_option_info
    dhcp_search_ip_on_mac
    dhcps_dns_setserver
    dhcps_dns_setserver_by_type
    dhcps_dns_getserver
    dhcps_dns_getserver_by_type
    dhcps_set_new_lease_cb
)

# Apply linker wrap for each function and force the __wrap_ symbol to be included
# The -u flag ensures the symbol is pulled in from the static library
foreach(func ${DHCPS_WRAP_FUNCTIONS})
    target_link_libraries(${COMPONENT_LIB} INTERFACE
        "-Wl,--wrap=${func}"
        "-u __wrap_${func}"
    )
endforeach()
