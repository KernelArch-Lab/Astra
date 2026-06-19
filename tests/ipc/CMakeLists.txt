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

# Sprint 4: HMAC-authenticated write/read (SHA-256 KAT + tamper detection)
add_executable(test_ipc_sprint4
    test_sprint4_hmac.cpp
)
target_link_libraries(test_ipc_sprint4
    PRIVATE
        astra_ipc
        astra_asm_core
        astra_core
        pthread
)
add_test(NAME Sprint4IpcHmacTest COMMAND test_ipc_sprint4)
message(STATUS "  [M-03] test_ipc_sprint4 configured")

# Sprint 5: Capability-gated write/read (CapabilityGate, IPC_SEND/IPC_RECV, revocation)
add_executable(test_ipc_sprint5
    test_sprint5_cap_gate.cpp
)
target_link_libraries(test_ipc_sprint5
    PRIVATE
        astra_ipc
        astra_core
        pthread
)
add_test(NAME Sprint5IpcCapGateTest COMMAND test_ipc_sprint5)
message(STATUS "  [M-03] test_ipc_sprint5 configured")

# Sprint 6: HKDF session-key derivation (RFC 5869, KAT + IPC integration)
add_executable(test_ipc_sprint6
    test_sprint6_hkdf.cpp
)
target_link_libraries(test_ipc_sprint6
    PRIVATE
        astra_ipc
        astra_asm_core
        astra_core
        pthread
)
add_test(NAME Sprint6IpcHkdfTest COMMAND test_ipc_sprint6)
message(STATUS "  [M-03] test_ipc_sprint6 configured")

# Sprint 16: Paper Benchmark Suite (multi-scenario, demo only)
add_executable(demo_ipc_paper_bench
    demo_ipc_paper_bench.cpp
)
target_link_libraries(demo_ipc_paper_bench
    PRIVATE
        astra_ipc
        astra_asm_core
        astra_core
        pthread
)
message(STATUS "  [M-03] demo_ipc_paper_bench configured")

# Sprint 15: Full Security Stack integration (S1+S4+S6+S7+S8+S9+S10)
add_executable(test_ipc_sprint15
    test_sprint15_full_stack.cpp
)
target_link_libraries(test_ipc_sprint15
    PRIVATE
        astra_ipc
        astra_asm_core
        astra_core
        pthread
)
add_test(NAME Sprint15IpcFullStackTest COMMAND test_ipc_sprint15)
message(STATUS "  [M-03] test_ipc_sprint15 configured")

# Sprint 14: Throughput Benchmark (demo only — not a ctest)
add_executable(demo_ipc_throughput
    demo_ipc_throughput.cpp
)
target_link_libraries(demo_ipc_throughput
    PRIVATE
        astra_ipc
        astra_core
        pthread
)
message(STATUS "  [M-03] demo_ipc_throughput configured")

# Sprint 13: Latency Histogram (LatencyTracker + LatencyHistogram)
add_executable(test_ipc_sprint13
    test_sprint13_latency.cpp
)
target_link_libraries(test_ipc_sprint13
    PRIVATE
        astra_ipc
        astra_core
        pthread
)
add_test(NAME Sprint13IpcLatencyTest COMMAND test_ipc_sprint13)
message(STATUS "  [M-03] test_ipc_sprint13 configured")

# Sprint 12: Zero-Copy Buffer Loan (BroadcastRing::loan / commit)
add_executable(test_ipc_sprint12
    test_sprint12_zero_copy.cpp
)
target_link_libraries(test_ipc_sprint12
    PRIVATE
        astra_ipc
        astra_core
        pthread
)
add_test(NAME Sprint12IpcZeroCopyTest COMMAND test_ipc_sprint12)
message(STATUS "  [M-03] test_ipc_sprint12 configured")

# Sprint 11: Multicast Fan-Out (BroadcastRing — single writer, N independent readers)
add_executable(test_ipc_sprint11
    test_sprint11_broadcast.cpp
)
target_link_libraries(test_ipc_sprint11
    PRIVATE
        astra_ipc
        astra_core
        pthread
)
add_test(NAME Sprint11IpcBroadcastTest COMMAND test_ipc_sprint11)
message(STATUS "  [M-03] test_ipc_sprint11 configured")

# Sprint 10: Channel Epoch / Revocation (revokeChannel, isRevoked, readChecked)
add_executable(test_ipc_sprint10
    test_sprint10_epoch.cpp
)
target_link_libraries(test_ipc_sprint10
    PRIVATE
        astra_ipc
        astra_core
        pthread
)
add_test(NAME Sprint10IpcEpochTest COMMAND test_ipc_sprint10)
message(STATUS "  [M-03] test_ipc_sprint10 configured")

# Sprint 9: Capacity Snapshot (occupancy() — used/total bytes + message/skip counts)
add_executable(test_ipc_sprint9
    test_sprint9_capacity.cpp
)
target_link_libraries(test_ipc_sprint9
    PRIVATE
        astra_ipc
        astra_core
        pthread
)
add_test(NAME Sprint9IpcCapacityTest COMMAND test_ipc_sprint9)
message(STATUS "  [M-03] test_ipc_sprint9 configured")

# Sprint 8: Replay Guard (readVerifySeq — HMAC + sequence monotonicity check)
add_executable(test_ipc_sprint8
    test_sprint8_replay_guard.cpp
)
target_link_libraries(test_ipc_sprint8
    PRIVATE
        astra_ipc
        astra_asm_core
        astra_core
        pthread
)
add_test(NAME Sprint8IpcReplayGuardTest COMMAND test_ipc_sprint8)
message(STATUS "  [M-03] test_ipc_sprint8 configured")

# Sprint 7: SCM_RIGHTS memfd fd-passing (sendFd / recvFd / mapReceivedChannel)
add_executable(test_ipc_sprint7
    test_sprint7_scm_rights.cpp
)
target_link_libraries(test_ipc_sprint7
    PRIVATE
        astra_ipc
        astra_core
        pthread
)
add_test(NAME Sprint7IpcScmRightsTest COMMAND test_ipc_sprint7)
message(STATUS "  [M-03] test_ipc_sprint7 configured")

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
