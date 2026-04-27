# ============================================================================
# Astra Runtime - Paper 1 baseline harnesses
# tests/bench/CMakeLists.txt
#
# Track B Sprint 6 of the Paper 1 (USENIX ATC 2027) prep work.
#
# Each binary in this directory measures one IPC transport and emits a
# single CSV table to stdout. Sprint 7's run_paper1_sweep.sh runs them in
# sequence and concatenates the rows into figure_1.csv.
#
# These are NOT registered as ctest gates — RDTSC numbers are noisy in
# shared CI runners and would falsely fail the test stage. They are built
# and runnable on demand:
#
#   cmake --build build --target paper1_baselines
#   ./scripts/run_paper1_sweep.sh
# ============================================================================

# --- Always-built baselines (POSIX-only deps) -------------------------------
add_executable(bench_baseline_pipe       baseline_pipe.cpp)
add_executable(bench_baseline_socketpair baseline_socketpair.cpp)
add_executable(bench_baseline_io_uring   baseline_io_uring.cpp)
add_executable(bench_baseline_astra      baseline_astra.cpp)
add_executable(bench_baseline_astra_gated baseline_astra_gated.cpp)
add_executable(bench_baseline_aeron      baseline_aeron.cpp)
add_executable(bench_baseline_erpc       baseline_erpc.cpp)

foreach(_bench
        bench_baseline_pipe
        bench_baseline_socketpair
        bench_baseline_io_uring
        bench_baseline_astra
        bench_baseline_astra_gated
        bench_baseline_aeron
        bench_baseline_erpc)
    target_include_directories(${_bench}
        PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(${_bench}
        PRIVATE
            pthread)
endforeach()

# --- Astra-side baselines need the runtime libs -----------------------------
target_link_libraries(bench_baseline_astra
    PRIVATE
        astra_ipc
        astra_core
        astra_asm_core)
target_link_libraries(bench_baseline_astra_gated
    PRIVATE
        astra_ipc
        astra_core
        astra_asm_core)

# --- io_uring: link liburing if present (otherwise the binary self-skips) ---
find_path(LIBURING_INCLUDE liburing.h)
find_library(LIBURING_LIB uring)
if(LIBURING_INCLUDE AND LIBURING_LIB)
    target_include_directories(bench_baseline_io_uring PRIVATE ${LIBURING_INCLUDE})
    target_link_libraries     (bench_baseline_io_uring PRIVATE ${LIBURING_LIB})
    message(STATUS "  [Paper-1] liburing found at ${LIBURING_LIB}")
else()
    message(STATUS "  [Paper-1] liburing not found — bench_baseline_io_uring will self-skip")
endif()

# --- Aeron: optional -I via -DAERON_DIR=/path/to/aeron-cpp/build ------------
if(AERON_DIR)
    target_include_directories(bench_baseline_aeron PRIVATE
        ${AERON_DIR}/aeron-client/src/main/cpp
        ${AERON_DIR}/aeron-driver/src/main/c
        ${AERON_DIR})
    target_link_libraries(bench_baseline_aeron PRIVATE
        ${AERON_DIR}/lib/libaeron_client.so)
    message(STATUS "  [Paper-1] Aeron at ${AERON_DIR}")
else()
    message(STATUS "  [Paper-1] AERON_DIR not set — bench_baseline_aeron will self-skip")
endif()

# --- eRPC: optional -I via -DERPC_DIR=/path/to/eRPC -------------------------
if(ERPC_DIR)
    target_include_directories(bench_baseline_erpc PRIVATE
        ${ERPC_DIR}/src
        ${ERPC_DIR})
    target_link_libraries(bench_baseline_erpc PRIVATE
        ${ERPC_DIR}/build/liberpc.a
        rt
        numa)
    message(STATUS "  [Paper-1] eRPC at ${ERPC_DIR}")
else()
    message(STATUS "  [Paper-1] ERPC_DIR not set — bench_baseline_erpc will self-skip")
endif()

# --- Convenience target: build them all ------------------------------------
add_custom_target(paper1_baselines DEPENDS
    bench_baseline_pipe
    bench_baseline_socketpair
    bench_baseline_io_uring
    bench_baseline_astra
    bench_baseline_astra_gated
    bench_baseline_aeron
    bench_baseline_erpc)

message(STATUS "[Paper-1] tests/bench targets configured (build with --target paper1_baselines)")
