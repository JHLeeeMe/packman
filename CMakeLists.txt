cmake_minimum_required(VERSION 3.10)
project(packman)

add_executable(packman main.cpp)
target_link_libraries(packman PRIVATE pcap)
