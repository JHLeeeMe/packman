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

# Create Targets
add_executable(CXX_Packman ${SRCS_G})

# PCH
target_precompile_headers(CXX_Packman PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include/pch.h)

# Include (-I)
target_include_directories(CXX_Packman
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/npcap>
)

# Lib (-L)
if(WIN32)
    target_link_directories(CXX_Packman
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/lib/npcap/x64>
    )
else()
endif()

# Link (-l)
if(WIN32)
    list(APPEND LIBS wpcap ws2_32)
elseif(UNIX AND NOT APPLE)
    list(APPEND LIBS pcap)
endif()
target_link_libraries(CXX_Packman
    PRIVATE
        ${LIBS}
)

# Predefine (-D)
if(WIN32)
    target_compile_definitions(CXX_Packman PUBLIC UNICODE _UNICODE)
else()
endif()

install(TARGETS CXX_Packman 
    RUNTIME DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
    LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
)
install(
    DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include
    DESTINATION ${CMAKE_INSTALL_PREFIX}
)

