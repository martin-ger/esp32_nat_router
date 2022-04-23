# The following lines of boilerplate have to be in your project's CMakeLists
# in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.5)

add_compile_definitions(IP_NAPT=1)

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(esp32_nat_router)
