idf_component_register(SRCS "cmd_system.c"
                    INCLUDE_DIRS .
                    REQUIRES console spi_flash driver nvs_flash cmd_router lwip)
target_compile_options(${COMPONENT_LIB} PRIVATE -Os)