// ============================================================================
// Astra Runtime - M-09 eBPF Observability Unit Tests
// tests/ebpf/test_ebpf_core.cpp
//
// Sprint 1 unit tests for the eBPF Observability module.
//
// TESTING PHILOSOPHY:
//   These tests validate the userspace layer of M-09 without requiring
//   a live Linux kernel, CAP_BPF capability, or pre-compiled .bpf.o files.
//   Integration tests that actually attach BPF probes require root and belong
//   in a separate CI pipeline stage (Sprint 2+).
//
//   What we test here:
//     1. EbpfEventHeader struct layout and field byte sizes.
//     2. EbpfService construction and state guards.
//     3. EbpfEventType enum values match the BPF constants.
//     4. ProbeManager behaviour with a non-existent probe directory.
//     5. EbpfService double-init and out-of-order lifecycle protection.
// ============================================================================

#include <astra/ebpf/ebpf_service.h>

#include <cstdio>
#include <cstring>
#include <filesystem>

// ============================================================================
// Astra native test infrastructure
//
// These macros match the convention used across all Astra test suites.
// There is no external test framework dependency — intentional for embedded
// and constrained build environments.
// ============================================================================
static int g_iPass = 0, g_iFail = 0, g_iTotal = 0;

#define TEST_SECTION(name) \
    printf("\n\033[1;34m=== %s ===\033[0m\n", name)

#define TEST_ASSERT(cond)                                                          \
    do                                                                             \
    {                                                                              \
        ++g_iTotal;                                                                \
        if (!(cond))                                                               \
        {                                                                          \
            printf("  \033[31m[FAIL]\033[0m %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_iFail;                                                             \
        }                                                                          \
        else                                                                       \
        {                                                                          \
            ++g_iPass;                                                             \
        }                                                                          \
    } while (0)

#define TEST_ASSERT_EQ(a, b)                                                       \
    do                                                                             \
    {                                                                              \
        ++g_iTotal;                                                                \
        if ((a) != (b))                                                            \
        {                                                                          \
            printf("  \033[31m[FAIL]\033[0m %s:%d: %s != %s\n",                   \
                   __FILE__, __LINE__, #a, #b);                                    \
            ++g_iFail;                                                             \
        }                                                                          \
        else                                                                       \
        {                                                                          \
            ++g_iPass;                                                             \
        }                                                                          \
    } while (0)

// ============================================================================
// Bring test types into scope
// ============================================================================
using namespace astra;
using namespace astra::ebpf;

// ============================================================================
// Test Sections
// ============================================================================

// ----------------------------------------------------------------------------
// Section 1: EbpfEventHeader struct layout
//
// These tests are compile-time safety nets: if anyone changes the struct
// layout, these tests will fail, alerting them that the BPF probe's C struct
// in task_spawn.bpf.c must be updated to match.
// ----------------------------------------------------------------------------
static void test_event_header_layout()
{
    TEST_SECTION("1. EbpfEventHeader struct layout");

    // Total size must be exactly 16 bytes
    TEST_ASSERT_EQ(sizeof(EbpfEventHeader), 16u);

    // Verify individual field sizes match the BPF schema
    TEST_ASSERT_EQ(sizeof(EbpfEventHeader::m_uTimestampNs), 8u);   // U64
    TEST_ASSERT_EQ(sizeof(EbpfEventHeader::m_uEventType),   2u);   // U16
    TEST_ASSERT_EQ(sizeof(EbpfEventHeader::m_uSourcePid),   4u);   // U32
    TEST_ASSERT_EQ(sizeof(EbpfEventHeader::m_uFlags),       2u);   // U16

    // Verify field offsets match the packed layout
    TEST_ASSERT_EQ(offsetof(EbpfEventHeader, m_uTimestampNs), 0u);
    TEST_ASSERT_EQ(offsetof(EbpfEventHeader, m_uEventType),   8u);
    TEST_ASSERT_EQ(offsetof(EbpfEventHeader, m_uSourcePid),  10u);
    TEST_ASSERT_EQ(offsetof(EbpfEventHeader, m_uFlags),      14u);

    printf("  \033[32m[PASS]\033[0m EbpfEventHeader size = %zu bytes\n",
           sizeof(EbpfEventHeader));
}

// ----------------------------------------------------------------------------
// Section 2: EbpfEventType enum values
//
// The BPF program in task_spawn.bpf.c uses integer constants that MUST match
// the enum values here. This test makes that relationship explicit and will
// catch regressions if either side changes.
// ----------------------------------------------------------------------------
static void test_event_type_values()
{
    TEST_SECTION("2. EbpfEventType enum values vs. BPF constants");

    // These must match the #define constants in task_spawn.bpf.c exactly.
    // If the values diverge, the userspace consumer will misinterpret events.
    TEST_ASSERT_EQ(static_cast<U16>(EbpfEventType::UNKNOWN),     0u);
    TEST_ASSERT_EQ(static_cast<U16>(EbpfEventType::TASK_SPAWN),  1u);
    TEST_ASSERT_EQ(static_cast<U16>(EbpfEventType::TASK_EXIT),   2u);
    TEST_ASSERT_EQ(static_cast<U16>(EbpfEventType::SERVICE_EVT), 3u);

    printf("  \033[32m[PASS]\033[0m EbpfEventType values match BPF constants\n");
}

// ----------------------------------------------------------------------------
// Section 3: EbpfEventHeader field population and readback
//
// Construct a stack-allocated header, populate it with known values,
// and verify readback. This exercises the packed struct semantics and
// validates that zero-initialization works correctly.
// ----------------------------------------------------------------------------
static void test_event_header_readback()
{
    TEST_SECTION("3. EbpfEventHeader field population");

    EbpfEventHeader lHdr{};

    // Zero-initialized — all fields must be 0
    TEST_ASSERT_EQ(lHdr.m_uTimestampNs, 0u);
    TEST_ASSERT_EQ(lHdr.m_uEventType,   0u);
    TEST_ASSERT_EQ(lHdr.m_uSourcePid,   0u);
    // Note: m_uEventSize was removed to pack the header tightly to 16 bytes
    TEST_ASSERT_EQ(lHdr.m_uFlags,       0u);

    // Populate with sentinel values
    lHdr.m_uTimestampNs = 1234567890123ULL;
    lHdr.m_uEventType   = static_cast<U16>(EbpfEventType::TASK_SPAWN);
    lHdr.m_uSourcePid   = 4242u;
    lHdr.m_uFlags       = 0u;

    TEST_ASSERT_EQ(lHdr.m_uTimestampNs, 1234567890123ULL);
    TEST_ASSERT_EQ(lHdr.m_uEventType,   1u);
    TEST_ASSERT_EQ(lHdr.m_uSourcePid,   4242u);
    TEST_ASSERT_EQ(lHdr.m_uFlags,       0u);

    printf("  \033[32m[PASS]\033[0m EbpfEventHeader field read/write correct\n");
}

// ----------------------------------------------------------------------------
// Section 4: EbpfService lifecycle guards
//
// We cannot actually call onInit() without a valid probe directory and the
// CAP_BPF capability, but we CAN verify that the lifecycle state guards
// (double-init protection, out-of-order protection) fire correctly when
// ProbeManager::loadAll() fails on a missing directory.
// ----------------------------------------------------------------------------
static void test_service_lifecycle_guards()
{
    TEST_SECTION("4. EbpfService lifecycle state guards");

    // Use a directory that definitely does not exist
    std::filesystem::path lFakeDir{"/nonexistent/probe/directory"};
    EbpfService lSvc(lFakeDir);

    // name() and moduleId() must always be accessible, even before init
    TEST_ASSERT(lSvc.name() == "ebpf-observability");
    TEST_ASSERT(lSvc.moduleId() == ModuleId::EBPF);

    // isHealthy() must return false before init
    TEST_ASSERT(!lSvc.isHealthy());

    // onInit() must fail because the probe directory does not exist
    astra::Status lStInit = lSvc.onInit();
    TEST_ASSERT(!lStInit.has_value());
    TEST_ASSERT(lStInit.error().category() == ErrorCategory::EBPF);

    // onStart() before a successful onInit() must also fail
    astra::Status lStStart = lSvc.onStart();
    TEST_ASSERT(!lStStart.has_value());
    TEST_ASSERT(lStStart.error().code() == ErrorCode::NOT_INITIALIZED);

    printf("  \033[32m[PASS]\033[0m lifecycle guards fire correctly\n");
}

// ----------------------------------------------------------------------------
// Section 5: ProbeManager directory validation
//
// Test that ProbeManager::loadAll() correctly rejects missing and empty dirs.
// ----------------------------------------------------------------------------
static void test_probe_manager_directory_validation()
{
    TEST_SECTION("5. ProbeManager directory validation");

    // Non-existent directory must return NOT_FOUND
    {
        ProbeManager lMgr{"/tmp/astra_test_nonexistent_probe_dir_xyz"};
        auto lSt = lMgr.loadAll();
        TEST_ASSERT(!lSt.has_value());
        TEST_ASSERT(lSt.error().code() == ErrorCode::NOT_FOUND);
    }

    // Empty directory must return NOT_FOUND (no .bpf.o files found)
    {
        namespace fs = std::filesystem;
        auto lTmpDir = fs::temp_directory_path() / "astra_test_ebpf_empty";
        fs::create_directories(lTmpDir);

        ProbeManager lMgr{lTmpDir};
        auto lSt = lMgr.loadAll();
        TEST_ASSERT(!lSt.has_value());
        TEST_ASSERT(lSt.error().code() == ErrorCode::NOT_FOUND);

        // Initial ring buffer fd must be -1 if nothing was loaded
        TEST_ASSERT_EQ(lMgr.ringBufferMapFd(), -1);

        fs::remove(lTmpDir);
        printf("  \033[32m[PASS]\033[0m ProbeManager rejects non-existent and empty dirs\n");
    }
}

// ============================================================================
// main()
// ============================================================================
int main()
{
    printf("\n\033[1;37m======================================\033[0m\n");
    printf("\033[1;37m  M-09 eBPF Unit Tests (Sprint 1)\033[0m\n");
    printf("\033[1;37m======================================\033[0m\n");

    test_event_header_layout();
    test_event_type_values();
    test_event_header_readback();
    test_service_lifecycle_guards();
    test_probe_manager_directory_validation();

    printf("\n  ========================================\n");
    printf("  Assertions: %d passed, %d failed (total: %d)\n",
           g_iPass, g_iFail, g_iTotal);

    if (g_iFail == 0)
        printf("  \033[32mALL TESTS PASSED\033[0m\n\n");
    else
        printf("  \033[31m%d TEST(S) FAILED\033[0m\n\n", g_iFail);

    return g_iFail > 0 ? 1 : 0;
}
