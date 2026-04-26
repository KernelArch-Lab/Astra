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

# Latency microbenchmark — Track B Sprint 3 of the Paper 1 prep.
# rdtscp + HDR-style percentiles. CI runs the threaded mode with a
# small sample count; the full Paper 1 figure is generated on a tuned
# host with --samples 1000000.
add_executable(bench_ipc_latency
    bench_latency.cpp
)
target_link_libraries(bench_ipc_latency
    PRIVATE
        astra_ipc
        astra_core
        pthread
)
add_test(
    NAME    Sprint3IpcLatencyBench
    COMMAND bench_ipc_latency --threaded --warmup 1000 --samples 5000
)
message(STATUS "  [M-03] bench_ipc_latency configured")
