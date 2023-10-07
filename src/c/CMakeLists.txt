# Sources
if(WIN32)
    file(GLOB SRCS_G *.c)
elseif(UNIX AND NOT APPLE)
    file(GLOB SRCS_G
        main.c
        pcap_ext.c)
else()
endif()

# Headers
file(GLOB HDRS_G include/*.h)

# Create Targets
add_executable(C_Packman ${SRCS_G})

# PCH
target_precompile_headers(C_Packman PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/pch.h)

# Include (-I)
target_include_directories(C_Packman
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
if(WIN32)
elseif(UNIX AND NOT APPLE)
    target_include_directories(C_Packman
        PUBLIC
            $<BUILD_INTERFACE:/usr/include>
    )
else()
endif()

# Predefine (-D)
if(WIN32)
    target_compile_definitions(C_Packman PUBLIC UNICODE _UNICODE)
elseif(UNIX AND NOT APPLE)
else()
endif()

install(
    FILES ${HDRS_G}
    DESTINATION ${CMAKE_INSTALL_PREFIX}/include
)
