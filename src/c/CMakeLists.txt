cmake_minimum_required(VERSION 3.10)
project(packman)

include_directories(include)
link_directories(lib)

add_executable(packman main.c pcap_ext.c)
target_link_libraries(packman)
