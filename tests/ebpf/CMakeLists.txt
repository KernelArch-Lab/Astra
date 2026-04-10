# ============================================================================
# Astra Runtime - M-09 eBPF Tests
# tests/ebpf/CMakeLists.txt
#
# Builds the test_ebpf executable for unit testing the userspace M-09 layer.
#
# NOTE: These tests do NOT require CAP_BPF or root privileges — they validate
# the C++ layer only (struct layouts, lifecycle guards, directory validation).
# BPF integration tests (actual probe attachment) are a Sprint 2+ concern and
# will be added to a separate CI stage that runs with elevated privileges.
# ============================================================================

add_executable(test_ebpf
    test_ebpf_core.cpp
)

# Force C++23 to match the core runtime build — std::expected and std::format
# are both used in ebpf_service.cpp and must be available here too.
set_target_properties(test_ebpf PROPERTIES
    CXX_STANDARD            23
    CXX_STANDARD_REQUIRED   ON
    CXX_EXTENSIONS          OFF
)

target_include_directories(test_ebpf
    PRIVATE
        ${CMAKE_SOURCE_DIR}/include  # astra/ebpf/ebpf_service.h, astra/common/*
)

target_link_libraries(test_ebpf
    PRIVATE
        astra_ebpf     # the module under test
        astra_core     # IService, Result<T>, makeError()
        bpf            # libbpf (needed by astra_ebpf transitively)
        elf            # libelf (needed by libbpf transitively)
        pthread        # std::thread used in EbpfService::onStart()
)

# Register with CTest so `ctest` discovers and runs the suite automatically.
add_test(
    NAME    EbpfUnitTests
    COMMAND test_ebpf
)

message(STATUS "  [M-09] test_ebpf configured")

# Live demo: shows eBPF observability pipeline working interactively
add_executable(demo_ebpf_live
    demo_ebpf_live.cpp
)

set_target_properties(demo_ebpf_live PROPERTIES
    CXX_STANDARD            23
    CXX_STANDARD_REQUIRED   ON
    CXX_EXTENSIONS          OFF
)

target_include_directories(demo_ebpf_live
    PRIVATE
        ${CMAKE_SOURCE_DIR}/include
)

target_link_libraries(demo_ebpf_live
    PRIVATE
        astra_ebpf
        astra_core
        bpf
        elf
        pthread
)

message(STATUS "  [M-09] demo_ebpf_live configured")
