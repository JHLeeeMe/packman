# Sources
file(GLOB SRCS_G
    main.c
    pcap_ext.c)

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

install(TARGETS C_Packman 
    RUNTIME DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
    LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
)
install(
    FILES ${HDRS_G}
    DESTINATION ${CMAKE_INSTALL_PREFIX}/include
)
