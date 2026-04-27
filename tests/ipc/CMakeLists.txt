# ============================================================================
# Astra Runtime - M-03 IPC Tests
# tests/ipc/CMakeLists.txt
# ============================================================================

# Sprint 1 original (Laakhi)
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

# Sprint 1 extended (real Astra data, SCM_RIGHTS simulation)
add_executable(test_ipc_sprint1_extended
    test_sprint1_extended.cpp
)
target_link_libraries(test_ipc_sprint1_extended
    PRIVATE
        astra_ipc
        astra_core
        pthread
)
add_test(NAME Sprint1IpcExtendedTest COMMAND test_ipc_sprint1_extended)
message(STATUS "  [M-03] test_ipc_sprint1_extended configured")

# Sprint 2 ring buffer (framing, FIFO, wraparound, backpressure)
add_executable(test_ipc_sprint2
    test_sprint2_ring_buffer.cpp
)
target_link_libraries(test_ipc_sprint2
    PRIVATE
        astra_ipc
        astra_core
        pthread
)
add_test(NAME Sprint2IpcRingBufferTest COMMAND test_ipc_sprint2)
message(STATUS "  [M-03] test_ipc_sprint2 configured")

# Sprint 2 MPSC (fetch_add + CAS paths, SKIP sentinel, concurrent producers)
add_executable(test_ipc_sprint2_mpsc
    test_sprint2_mpsc.cpp
)
target_link_libraries(test_ipc_sprint2_mpsc
    PRIVATE
        astra_ipc
        astra_core
        pthread
)
add_test(NAME Sprint2IpcMpscTest COMMAND test_ipc_sprint2_mpsc)
message(STATUS "  [M-03] test_ipc_sprint2_mpsc configured")

# Sprint 3 wait/notify (futex-based blocking read, no busy-wait)
add_executable(test_ipc_sprint3
    test_sprint3_wait_notify.cpp
)
target_link_libraries(test_ipc_sprint3
    PRIVATE
        astra_ipc
        astra_core
        pthread
)
add_test(NAME Sprint3IpcWaitNotifyTest COMMAND test_ipc_sprint3)
message(STATUS "  [M-03] test_ipc_sprint3 configured")

# Sprint 5 capability-gate tests (Paper 1 hot-path correctness)
add_executable(test_ipc_sprint5_cap_gate
    test_sprint5_cap_gate.cpp
)
target_link_libraries(test_ipc_sprint5_cap_gate
    PRIVATE
        astra_ipc
        astra_core
        astra_asm_core
        pthread
)
add_test(NAME Sprint5IpcCapGateTest COMMAND test_ipc_sprint5_cap_gate)
message(STATUS "  [M-03] test_ipc_sprint5_cap_gate configured")

# Sprint 5 microbench: gate-on vs gate-off latency (Paper 1 headline figure)
add_executable(bench_ipc_with_gate
    bench_ipc_with_gate.cpp
)
target_link_libraries(bench_ipc_with_gate
    PRIVATE
        astra_ipc
        astra_core
        astra_asm_core
        pthread
)
message(STATUS "  [M-03] bench_ipc_with_gate configured")

# Live demo: shows IPC working interactively in the terminal
add_executable(demo_ipc_live
    demo_ipc_live.cpp
)
target_link_libraries(demo_ipc_live
    PRIVATE
        astra_ipc
        astra_core
        pthread
)
message(STATUS "  [M-03] demo_ipc_live configured")
