# ============================================================================
# Astra Runtime - M-03 IPC Tests
# tests/ipc/CMakeLists.txt
# ============================================================================

add_executable(test_ipc_sprint1
    test_sprint1_channel_factory.cpp
)

target_link_libraries(test_ipc_sprint1
    PRIVATE
        astra_ipc
        astra_core
        pthread
)

add_test(NAME Sprint1IpcChannelFactoryTest COMMAND test_ipc_sprint1)

message(STATUS "  [M-03] test_ipc_sprint1 configured")
