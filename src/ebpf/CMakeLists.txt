# ============================================================================
# Astra Runtime - M-09 eBPF Observability Microservice
# src/ebpf/CMakeLists.txt
#
# Build targets:
#   astra_ebpf         — C++ static library (ProbeManager, EbpfService, etc.)
#   task_spawn.bpf.o   — Kernel-side BPF object compiled by clang -target bpf
#
# IMPORTANT: Two separate compilers are involved in this directory:
#   1. The host C++ compiler (g++ 13) compiles ebpf_service.cpp into astra_ebpf.
#   2. clang compiles task_spawn.bpf.c into a BPF ELF object (task_spawn.bpf.o).
#      The BPF object is NOT linked into the C++ target; it is loaded at
#      runtime by ProbeManager from the probe output directory.
# ============================================================================

# ============================================================================
# BPF Probe Compilation
#
# Finds the clang compiler and produces task_spawn.bpf.o via a custom_command.
# The output is placed in the "probes" subdirectory of the build output tree,
# which is the flat directory ProbeManager reads from at process startup.
# ============================================================================
find_program(CLANG_BPF_COMPILER clang REQUIRED
    DOC "clang is required to compile BPF CO-RE probe programs at build time"
)

# The flat output directory from which ProbeManager will load .bpf.o files.
set(ASTRA_BPF_PROBE_OUTPUT_DIR "${CMAKE_BINARY_DIR}/probes")
file(MAKE_DIRECTORY "${ASTRA_BPF_PROBE_OUTPUT_DIR}")

# Source and output paths for the task_spawn probe
set(TASK_SPAWN_SRC   "${CMAKE_CURRENT_SOURCE_DIR}/probes/task_spawn.bpf.c")
set(TASK_SPAWN_OBJ   "${ASTRA_BPF_PROBE_OUTPUT_DIR}/task_spawn.bpf.o")

# vmlinux.h must be generated per-host machine using:
#   bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
# We place it alongside the .bpf.c source files to keep CO-RE artifacts together.
set(VMLINUX_H "${CMAKE_CURRENT_SOURCE_DIR}/probes/vmlinux.h")

# Custom build command to invoke clang as a BPF compiler.
# Flags explained:
#   -g              — include BTF debug info for CO-RE relocations
#   -O2             — BPF verifier requires optimized code
#   -target bpf     — tell clang to generate BPF bytecode (not native x86)
#   -D__TARGET_ARCH_x86 — required by bpf/bpf_tracing.h for register access
#   -I              — find vmlinux.h and libbpf headers
add_custom_command(
    OUTPUT  "${TASK_SPAWN_OBJ}"
    COMMAND "${CLANG_BPF_COMPILER}"
            -g
            -O2
            -target bpf
            -D__TARGET_ARCH_x86
            -I "${CMAKE_CURRENT_SOURCE_DIR}/probes"
            -I "/usr/include/bpf"
            -c "${TASK_SPAWN_SRC}"
            -o "${TASK_SPAWN_OBJ}"
    DEPENDS "${TASK_SPAWN_SRC}" "${VMLINUX_H}"
    COMMENT "[M-09] Compiling eBPF CO-RE probe: task_spawn.bpf.c -> task_spawn.bpf.o"
    VERBATIM
)

# Named target so we can do: cmake --build . --target astra_ebpf_probes
add_custom_target(astra_ebpf_probes ALL
    DEPENDS "${TASK_SPAWN_OBJ}"
)

# ============================================================================
# C++ Library: astra_ebpf
#
# Contains all userspace eBPF infrastructure:
#   - ProbeManager (BPF object loading and USDT attachment)
#   - RingBufferPoller (epoll-based event ingestion)
#   - EbpfService     (IService implementation for M-01 integration)
# ============================================================================
add_library(astra_ebpf STATIC
    ebpf_service.cpp
)

# astra_ebpf must be built AFTER the BPF probe objects are compiled,
# because ProbeManager references the probe output directory path at runtime.
add_dependencies(astra_ebpf astra_ebpf_probes)

target_include_directories(astra_ebpf
    PUBLIC
        ${CMAKE_SOURCE_DIR}/include  # astra/ebpf/ebpf_service.h, astra/core/*, etc.
)

# Pass the probe output directory as a compile-time constant so EbpfService
# knows where to find the .bpf.o files without hardcoding a path.
target_compile_definitions(astra_ebpf
    PRIVATE
        ASTRA_BPF_PROBE_DIR="${ASTRA_BPF_PROBE_OUTPUT_DIR}"
)

target_link_libraries(astra_ebpf
    PUBLIC
        astra_core     # IService, Result<T>, logging
    PRIVATE
        bpf            # libbpf — bpf_object__open, ring_buffer__new, etc.
        elf            # libelf — required by libbpf for ELF parsing
        pthread        # std::thread in EbpfService::onStart()
)

message(STATUS "  [M-09] astra_ebpf library configured")
message(STATUS "  [M-09] BPF probe output dir: ${ASTRA_BPF_PROBE_OUTPUT_DIR}")
