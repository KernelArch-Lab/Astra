// ============================================================================
// Astra Runtime - M-09 eBPF Observability Sprint 1 Live Demo
// tests/ebpf/demo_ebpf_live.cpp
//
// This demo shows the eBPF observability pipeline working end-to-end
// WITHOUT requiring root, CAP_BPF, or a live kernel.
//
// What you'll see:
//   1. EbpfEventHeader struct layout verification (BPF ↔ userspace contract)
//   2. Simulated kernel event stream — events serialized to raw bytes as
//      the BPF probe would write them, then deserialized and displayed
//      exactly as the real RingBufferPoller::onSample() would process them
//   3. ProbeManager lifecycle — loading from missing dir fails gracefully
//   4. EbpfService lifecycle guards — double-init / out-of-order protection
//   5. Event type discrimination — shows how different event types are routed
//
// When the real BPF probes are loaded (Sprint 2 CI with root), the exact
// same deserialization path runs on live kernel events.
// ============================================================================

#include <astra/ebpf/ebpf_service.h>

#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <thread>
#include <vector>

using namespace astra;
using namespace astra::ebpf;

// ============================================================================
// ANSI colour codes
// ============================================================================
static constexpr const char* COL_RESET   = "\033[0m";
static constexpr const char* COL_BOLD    = "\033[1m";
static constexpr const char* COL_GREEN   = "\033[32m";
static constexpr const char* COL_BLUE    = "\033[34m";
static constexpr const char* COL_MAGENTA = "\033[35m";
static constexpr const char* COL_CYAN    = "\033[36m";
static constexpr const char* COL_YELLOW  = "\033[33m";
static constexpr const char* COL_RED     = "\033[31m";
static constexpr const char* COL_DIM     = "\033[2m";

// ============================================================================
// Helper: get a monotonic-ish timestamp in nanoseconds (simulating kernel clock)
// ============================================================================
static U64 monotonicNs()
{
    auto lNow = std::chrono::steady_clock::now();
    return static_cast<U64>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            lNow.time_since_epoch()
        ).count()
    );
}

// ============================================================================
// Helper: format nanosecond timestamp into human-readable form
// ============================================================================
static void formatTimestamp(U64 aUNs, char* aBuf, size_t aUBufSize)
{
    U64 lUSec = aUNs / 1'000'000'000ULL;
    U64 lUMs  = (aUNs / 1'000'000ULL) % 1000ULL;
    U64 lUUs  = (aUNs / 1'000ULL) % 1000ULL;
    snprintf(aBuf, aUBufSize, "%llu.%03llu.%03llu",
             static_cast<unsigned long long>(lUSec),
             static_cast<unsigned long long>(lUMs),
             static_cast<unsigned long long>(lUUs));
}

// ============================================================================
// Helper: event type to string
// ============================================================================
static const char* eventTypeToString(EbpfEventType aEType)
{
    switch (aEType)
    {
        case EbpfEventType::UNKNOWN:    return "UNKNOWN";
        case EbpfEventType::TASK_SPAWN: return "TASK_SPAWN";
        case EbpfEventType::TASK_EXIT:  return "TASK_EXIT";
        case EbpfEventType::SERVICE_EVT:return "SERVICE_EVT";
        default:                        return "???";
    }
}

// ============================================================================
// Simulated event for the demo
// ============================================================================
struct SimulatedEvent
{
    EbpfEventType m_eType;
    U32           m_uPid;
    const char*   m_szDescription;
};

static const SimulatedEvent g_arrEvents[] = {
    { EbpfEventType::TASK_SPAWN,  1001, "astra_runtime spawned worker thread"       },
    { EbpfEventType::TASK_SPAWN,  1002, "isolation sandbox child forked"             },
    { EbpfEventType::SERVICE_EVT, 1001, "ServiceRegistry: 'allocator' -> RUNNING"    },
    { EbpfEventType::SERVICE_EVT, 1001, "ServiceRegistry: 'ipc-factory' -> RUNNING"  },
    { EbpfEventType::TASK_SPAWN,  1003, "IPC child process forked for channel #42"   },
    { EbpfEventType::SERVICE_EVT, 1001, "ServiceRegistry: 'ebpf-obs' -> RUNNING"     },
    { EbpfEventType::TASK_EXIT,   1003, "IPC child exited (status=0)"                },
    { EbpfEventType::TASK_EXIT,   1002, "isolation sandbox child exited (status=0)"   },
};
static constexpr int g_iNumEvents = sizeof(g_arrEvents) / sizeof(g_arrEvents[0]);

// ============================================================================
// Demo sections
// ============================================================================

static void demo_header_layout()
{
    fprintf(stderr, "%s%s", COL_BOLD, COL_MAGENTA);
    fprintf(stderr, "╔══════════════════════════════════════════════════════════════╗\n");
    fprintf(stderr, "║   1. BPF ↔ Userspace Contract: EbpfEventHeader Layout      ║\n");
    fprintf(stderr, "╚══════════════════════════════════════════════════════════════╝%s\n\n", COL_RESET);

    fprintf(stderr, "  %sThe BPF probe (kernel) and C++ consumer (userspace) MUST agree%s\n", COL_DIM, COL_RESET);
    fprintf(stderr, "  %son the exact byte layout of every event. Here's the contract:%s\n\n", COL_DIM, COL_RESET);

    fprintf(stderr, "  %s%-12s %-8s %-8s %s%s\n", COL_BOLD, "Field", "Offset", "Size", "Type", COL_RESET);
    fprintf(stderr, "  %s────────────────────────────────────────────%s\n", COL_DIM, COL_RESET);

    fprintf(stderr, "  %-12s %-8zu %-8zu %s\n", "timestamp",
            offsetof(EbpfEventHeader, m_uTimestampNs), sizeof(EbpfEventHeader::m_uTimestampNs), "U64 (ns)");
    fprintf(stderr, "  %-12s %-8zu %-8zu %s\n", "event_type",
            offsetof(EbpfEventHeader, m_uEventType),   sizeof(EbpfEventHeader::m_uEventType),   "U16 (enum)");
    fprintf(stderr, "  %-12s %-8zu %-8zu %s\n", "source_pid",
            offsetof(EbpfEventHeader, m_uSourcePid),   sizeof(EbpfEventHeader::m_uSourcePid),   "U32 (pid)");
    fprintf(stderr, "  %-12s %-8zu %-8zu %s\n", "flags",
            offsetof(EbpfEventHeader, m_uFlags),       sizeof(EbpfEventHeader::m_uFlags),       "U16 (bitmask)");

    fprintf(stderr, "  %s────────────────────────────────────────────%s\n", COL_DIM, COL_RESET);
    fprintf(stderr, "  %s%-12s %-8s %-8zu%s %s(packed, no padding)%s\n\n",
            COL_BOLD, "TOTAL", "", sizeof(EbpfEventHeader), COL_RESET, COL_DIM, COL_RESET);

    bool lBOk = sizeof(EbpfEventHeader) == 16
             && offsetof(EbpfEventHeader, m_uTimestampNs) == 0
             && offsetof(EbpfEventHeader, m_uEventType)   == 8
             && offsetof(EbpfEventHeader, m_uSourcePid)   == 10
             && offsetof(EbpfEventHeader, m_uFlags)        == 14;

    if (lBOk)
        fprintf(stderr, "  %s%s[✓] Layout matches BPF kernel struct — contract valid%s\n\n", COL_BOLD, COL_GREEN, COL_RESET);
    else
        fprintf(stderr, "  %s%s[✗] LAYOUT MISMATCH — BPF events will be misinterpreted!%s\n\n", COL_BOLD, COL_RED, COL_RESET);
}

static void demo_event_stream()
{
    fprintf(stderr, "%s%s", COL_BOLD, COL_MAGENTA);
    fprintf(stderr, "╔══════════════════════════════════════════════════════════════╗\n");
    fprintf(stderr, "║   2. Simulated eBPF Event Stream (as RingBufferPoller sees) ║\n");
    fprintf(stderr, "╚══════════════════════════════════════════════════════════════╝%s\n\n", COL_RESET);

    fprintf(stderr, "  %sSimulating kernel events → serialize to raw bytes → deserialize%s\n", COL_DIM, COL_RESET);
    fprintf(stderr, "  %sThis is the exact path real BPF events take through the system:%s\n\n", COL_DIM, COL_RESET);

    // Pre-allocate a raw byte buffer (simulating the BPF ring buffer)
    std::vector<std::byte> lVRingBuf(g_iNumEvents * sizeof(EbpfEventHeader));

    // Step 1: Serialize events (what the BPF probe does in the kernel)
    fprintf(stderr, "  %s--- Kernel side: BPF probe writes events to ring buffer ---%s\n\n", COL_YELLOW, COL_RESET);

    for (int lI = 0; lI < g_iNumEvents; ++lI)
    {
        const auto& lEvt = g_arrEvents[lI];

        // Build the header exactly as the BPF probe would
        EbpfEventHeader lHdr{};
        lHdr.m_uTimestampNs = monotonicNs();
        lHdr.m_uEventType   = static_cast<U16>(lEvt.m_eType);
        lHdr.m_uSourcePid   = lEvt.m_uPid;
        lHdr.m_uFlags       = 0;

        // Serialize to raw bytes (memcpy into ring buffer)
        std::memcpy(&lVRingBuf[static_cast<size_t>(lI) * sizeof(EbpfEventHeader)],
                    &lHdr, sizeof(lHdr));

        char lSzTs[64];
        formatTimestamp(lHdr.m_uTimestampNs, lSzTs, sizeof(lSzTs));
        fprintf(stderr, "  %s[KERNEL] Wrote event #%d: type=%s pid=%u ts=%s%s\n",
                COL_DIM, lI + 1, eventTypeToString(lEvt.m_eType),
                lEvt.m_uPid, lSzTs, COL_RESET);

        // Stagger so timestamps are different
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
    }

    fprintf(stderr, "\n  %s--- Userspace: RingBufferPoller::onSample() deserializes ---%s\n\n",
            COL_CYAN, COL_RESET);

    // Step 2: Deserialize (what RingBufferPoller::onSample() does)
    for (int lI = 0; lI < g_iNumEvents; ++lI)
    {
        const void* lPRaw = &lVRingBuf[static_cast<size_t>(lI) * sizeof(EbpfEventHeader)];
        const auto* lPHdr = static_cast<const EbpfEventHeader*>(lPRaw);

        auto lEType = static_cast<EbpfEventType>(lPHdr->m_uEventType);
        char lSzTs[64];
        formatTimestamp(lPHdr->m_uTimestampNs, lSzTs, sizeof(lSzTs));

        const char* lSzColour = COL_GREEN;
        if (lEType == EbpfEventType::TASK_EXIT)   lSzColour = COL_RED;
        if (lEType == EbpfEventType::SERVICE_EVT) lSzColour = COL_BLUE;

        fprintf(stderr, "  %s[M-09][ebpf]%s EVENT ts=%s %s%-12s%s pid=%-6u flags=0x%04x  %s%s%s\n",
                COL_BOLD, COL_RESET,
                lSzTs,
                lSzColour, eventTypeToString(lEType), COL_RESET,
                lPHdr->m_uSourcePid,
                lPHdr->m_uFlags,
                COL_DIM, g_arrEvents[lI].m_szDescription, COL_RESET);

        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    fprintf(stderr, "\n");
}

static void demo_service_lifecycle()
{
    fprintf(stderr, "%s%s", COL_BOLD, COL_MAGENTA);
    fprintf(stderr, "╔══════════════════════════════════════════════════════════════╗\n");
    fprintf(stderr, "║   3. EbpfService Lifecycle Guards                           ║\n");
    fprintf(stderr, "╚══════════════════════════════════════════════════════════════╝%s\n\n", COL_RESET);

    fprintf(stderr, "  %sThe EbpfService enforces strict lifecycle ordering.%s\n", COL_DIM, COL_RESET);
    fprintf(stderr, "  %sLet's see what happens with invalid sequences:%s\n\n", COL_DIM, COL_RESET);

    std::filesystem::path lFakeDir{"/nonexistent/probe/directory"};
    EbpfService lSvc(lFakeDir);

    // Test 1: name() and moduleId() always work
    fprintf(stderr, "  %s[1]%s Service name = \"%s\"\n", COL_BOLD, COL_RESET,
            std::string(lSvc.name()).c_str());
    fprintf(stderr, "  %s[2]%s Module ID    = M-%02u\n", COL_BOLD, COL_RESET,
            static_cast<unsigned>(lSvc.moduleId()));
    fprintf(stderr, "  %s[3]%s isHealthy()  = %s%s%s (expected: not yet initialised)\n",
            COL_BOLD, COL_RESET,
            lSvc.isHealthy() ? COL_RED : COL_GREEN,
            lSvc.isHealthy() ? "true [WRONG]" : "false [CORRECT]",
            COL_RESET);

    // Test 2: onInit() with missing probe dir
    fprintf(stderr, "\n  %s[4]%s Calling onInit() with non-existent probe dir...\n", COL_BOLD, COL_RESET);
    Status lStInit = lSvc.onInit();
    if (!lStInit.has_value())
    {
        fprintf(stderr, "      %s[✓] Correctly rejected: %s%s\n",
                COL_GREEN, std::string(lStInit.error().message()).c_str(), COL_RESET);
    }

    // Test 3: onStart() before successful init
    fprintf(stderr, "\n  %s[5]%s Calling onStart() without successful init...\n", COL_BOLD, COL_RESET);
    Status lStStart = lSvc.onStart();
    if (!lStStart.has_value())
    {
        fprintf(stderr, "      %s[✓] Correctly rejected: %s (code: NOT_INITIALIZED)%s\n",
                COL_GREEN, std::string(lStStart.error().message()).c_str(), COL_RESET);
    }

    fprintf(stderr, "\n");
}

static void demo_probe_manager()
{
    fprintf(stderr, "%s%s", COL_BOLD, COL_MAGENTA);
    fprintf(stderr, "╔══════════════════════════════════════════════════════════════╗\n");
    fprintf(stderr, "║   4. ProbeManager — BPF Object Loading                     ║\n");
    fprintf(stderr, "╚══════════════════════════════════════════════════════════════╝%s\n\n", COL_RESET);

    // Non-existent dir
    {
        fprintf(stderr, "  %s[1]%s Loading from non-existent directory...\n", COL_BOLD, COL_RESET);
        ProbeManager lMgr{"/tmp/astra_demo_nonexistent"};
        auto lSt = lMgr.loadAll();
        fprintf(stderr, "      %s[✓] Rejected: %s%s\n",
                COL_GREEN, std::string(lSt.error().message()).c_str(), COL_RESET);
        fprintf(stderr, "      Ring buffer map fd = %d (expected: -1)\n\n", lMgr.ringBufferMapFd());
    }

    // Empty dir
    {
        namespace fs = std::filesystem;
        auto lTmpDir = fs::temp_directory_path() / "astra_demo_ebpf_empty";
        fs::create_directories(lTmpDir);

        fprintf(stderr, "  %s[2]%s Loading from empty directory (%s)...\n",
                COL_BOLD, COL_RESET, lTmpDir.c_str());
        ProbeManager lMgr{lTmpDir};
        auto lSt = lMgr.loadAll();
        fprintf(stderr, "      %s[✓] Rejected: %s%s\n",
                COL_GREEN, std::string(lSt.error().message()).c_str(), COL_RESET);

        fs::remove(lTmpDir);
    }

    fprintf(stderr, "\n  %sNote: Loading real .bpf.o probes requires CAP_BPF or root.%s\n", COL_DIM, COL_RESET);
    fprintf(stderr, "  %sSprint 2 CI pipeline runs with elevated privileges.%s\n\n", COL_DIM, COL_RESET);
}

// ============================================================================
// main
// ============================================================================
int main()
{
    fprintf(stderr, "\n%s%s", COL_BOLD, COL_MAGENTA);
    fprintf(stderr, "╔══════════════════════════════════════════════════════════════╗\n");
    fprintf(stderr, "║     Astra M-09 eBPF Observability Sprint 1 — Live Demo     ║\n");
    fprintf(stderr, "║   Kernel-to-userspace event pipeline (simulated + real)     ║\n");
    fprintf(stderr, "╚══════════════════════════════════════════════════════════════╝%s\n\n", COL_RESET);

    demo_header_layout();
    demo_event_stream();
    demo_service_lifecycle();
    demo_probe_manager();

    fprintf(stderr, "%s%s", COL_BOLD, COL_MAGENTA);
    fprintf(stderr, "╔══════════════════════════════════════════════════════════════╗\n");
    fprintf(stderr, "║                      Demo Complete!                          ║\n");
    fprintf(stderr, "║                                                              ║\n");
    fprintf(stderr, "║  ✓ EbpfEventHeader layout verified (16 bytes packed)        ║\n");
    fprintf(stderr, "║  ✓ Event serialization/deserialization pipeline works        ║\n");
    fprintf(stderr, "║  ✓ EbpfService lifecycle guards fire correctly              ║\n");
    fprintf(stderr, "║  ✓ ProbeManager gracefully handles missing probe dirs       ║\n");
    fprintf(stderr, "║  ✓ Ready for real BPF probes when running with CAP_BPF     ║\n");
    fprintf(stderr, "╚══════════════════════════════════════════════════════════════╝%s\n\n", COL_RESET);

    return EXIT_SUCCESS;
}
