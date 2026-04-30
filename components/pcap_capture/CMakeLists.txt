idf_component_register(SRCS "pcap_capture.c" "pcap_ringbuf.c"
                    INCLUDE_DIRS "include"
                    REQUIRES lwip freertos esp_timer)
target_compile_options(${COMPONENT_LIB} PRIVATE -O2)
