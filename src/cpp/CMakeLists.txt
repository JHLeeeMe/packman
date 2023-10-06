# Sources
if(WIN32)
    file(GLOB SRCS_G *.cpp)
elseif(UNIX AND NOT APPLE)
    file(GLOB SRCS_G
        callback.cpp
        main.cpp
        packet_reader.cpp)
else()
endif()

# Headers
file(GLOB HDRS_G include/*.h*)

# Create Targets
add_executable(CXX_Packman ${SRCS_G})

# PCH
target_precompile_headers(CXX_Packman PRIVATE include/pch.h)

# Include (-I)
target_include_directories(CXX_Packman
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        if(WIN32)
        elseif(UNIX AND NOT APPLE)
            $<BUILD_INTERFACE:/usr/include>
        else()
        endif()
)

# Link (-l)
target_link_libraries(CXX_Packman
    PRIVATE
        pcap
)

# Predefine (-D)
if(WIN32)
    target_compile_definitions(CXX_Packman PUBLIC UNICODE _UNICODE)
else()
endif()

install(
    FILES ${HDRS_G}
    DESTINATION ${CMAKE_INSTALL_PREFIX}/include
)
