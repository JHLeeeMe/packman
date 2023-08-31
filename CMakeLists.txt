cmake_minimum_required(VERSION 3.10)
project(Packman)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
# Windows DLLs are "runtime" for CMake.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Append our module directory to CMake
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)  # -fPIC
add_subdirectory(src/c)
add_subdirectory(src/cpp)

message(STATUS "CMake Version:          ${CMAKE_VERSION}")
message(STATUS "Project:                ${PROJECT_NAME}")
message(STATUS "Generator:              ${CMAKE_GENERATOR}")
message(STATUS "Bulid for OS type:      ${CMAKE_SYSTEM_NAME}")
message(STATUS "Build for OS version:   ${CMAKE_SYSTEM_VERSION}")
message(STATUS "Build for CPU type:     ${CMAKE_SYSTEM_PROCESSOR}")
message(STATUS "Build type:             ${CMAKE_BUILD_TYPE}")
string(TOUPPER ${CMAKE_BUILD_TYPE} BUILD_TYPE)
message(STATUS "C flags:                ${CMAKE_C_FLAGS_${BUILD_TYPE}} ${CMAKE_C_FLAGS}")
message(STATUS "CXX flags:              ${CMAKE_CXX_FLAGS_${BUILD_TYPE}} ${CMAKE_CXX_FLAGS}")
message(STATUS "Build output path:      ${CMAKE_BINARY_DIR}")
message(STATUS "Install path:           ${CMAKE_INSTALL_PREFIX}")
