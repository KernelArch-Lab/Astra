# ============================================================================
# Astra Runtime - M-03 IPC
# src/ipc/CMakeLists.txt
# ============================================================================

add_library(astra_ipc STATIC
    ChannelFactory.cpp
    RingBuffer.cpp
)

target_include_directories(astra_ipc
    PUBLIC
        ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(astra_ipc
    PUBLIC
        astra_core
)

message(STATUS "  [M-03] astra_ipc library configured")
