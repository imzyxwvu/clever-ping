cmake_minimum_required(VERSION 3.9)
project(clever-ping C)

set(CMAKE_C_STANDARD 99)
find_package(PkgConfig REQUIRED)
pkg_search_module(LIBUV REQUIRED libuv)
find_library(HTTP_PARSER NAMES http_parser)
pkg_search_module(JSON_C REQUIRED json-c)

include_directories(${JSON_C_INCLUDE_DIRS})
add_executable(clever-ping
        src/main.c src/common.h src/common.c src/icmp.c src/api.c)
target_link_libraries(clever-ping
        ${LIBUV_LIBRARIES} ${HTTP_PARSER} ${JSON_C_LIBRARIES})