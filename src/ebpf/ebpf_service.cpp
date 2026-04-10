// ============================================================================
// Astra Runtime - M-09 eBPF Observability Microservice
// src/ebpf/ebpf_service.cpp
//
// Implementation of EbpfService, ProbeManager, and RingBufferPoller.
//
// READ THIS FIRST - Threading model:
//   This file has two execution contexts:
//
//   [Context A: Service Registry thread]
//     - EbpfService::onInit()  → ProbeManager::loadAll()
//     - EbpfService::onStart() → RingBufferPoller::init() + thread launch
//     - EbpfService::onStop()  → RingBufferPoller::stop() + thread join
//
//   [Context B: Ingestion thread (m_ingestionThread)]
//     - RingBufferPoller::pollLoop() runs here exclusively.
//     - The only shared state between A and B is m_bRunning (atomic).
//
//   TODO(Sprint 2): Replace m_ingestionThread (raw std::thread) with a
//   task submitted to EbpfThreadPool so the runtime can manage thread
//   lifecycles centrally. See design doc §4.2 "Async Thread Pool".
// ============================================================================
#include <astra/ebpf/ebpf_service.h>
#include <astra/core/logger.h>
#include <astra/common/result.h>

// libbpf: the userspace BPF library we use to load/attach programs and
// consume ring buffers. Linked via -lbpf in src/ebpf/CMakeLists.txt.
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

// POSIX headers for epoll and file descriptors
#include <cerrno>
#include <cstring>
#include <sys/epoll.h>
#include <unistd.h>

// C++ standard library
#include <cstdio>
#include <filesystem>
#include <format>
#include <string>

// ============================================================================
// Module logger definition.
// MUST appear exactly once per module (single translation unit).
// Expands to: ::astra::core::Logger g_logEbpf;
// ============================================================================
ASTRA_DEFINE_LOGGER(g_logEbpf);

// ============================================================================
// Internal constants
// ============================================================================
namespace
{
    // Maximum events drained per epoll_wait call.
    // Prevents starvation of other work if the ring buffer floods.
    constexpr int    k_iMaxEpollEvents = 8;

    // epoll_wait timeout in milliseconds. The thread wakes every
    // k_iEpollTimeoutMs even when idle, so it can check m_bRunning.
    constexpr int    k_iEpollTimeoutMs = 200;

    // Name of the BPF map we look up for the shared ring buffer.
    // Must exactly match the map name in task_spawn.bpf.c.
    constexpr char   k_szRingBufMapName[] = "shared_ringbuf";

} // anonymous namespace

namespace astra
{
namespace ebpf
{

// ============================================================================
// ProbeManager Implementation
// ============================================================================

ProbeManager::ProbeManager(std::filesystem::path aProbeDir) noexcept
    : m_probeDir(std::move(aProbeDir))
    , m_iRingBufMapFd(-1)
{
}

ProbeManager::~ProbeManager()
{
    // Ensure all BPF objects are cleaned up even if the user forgets
    // to call unloadAll() explicitly.
    unloadAll();
}

// ----------------------------------------------------------------------------
// loadAll()
//
// Scans m_probeDir for every file whose extension is ".bpf.o" and loads
// each one. The scan is non-recursive — we only look in the flat directory.
//
// If any single probe fails to load we log a warning and continue; a
// partial observability setup is better than no observability at all.
// The function returns OK as long as at least one probe was loaded.
// ----------------------------------------------------------------------------
Status ProbeManager::loadAll() noexcept
{
    LOG_INFO(g_logEbpf, "ProbeManager: scanning " << m_probeDir.string() << " for .bpf.o files");

    if (!std::filesystem::exists(m_probeDir))
    {
        return std::unexpected(makeError(
            ErrorCode::NOT_FOUND,
            ErrorCategory::EBPF,
            std::format("Probe directory does not exist: {}", m_probeDir.string())
        ));
    }

    std::error_code lEc;
    int lILoaded = 0;

    for (const auto& lEntry : std::filesystem::directory_iterator(m_probeDir, lEc))
    {
        if (lEc)
        {
            LOG_WARN(g_logEbpf, "ProbeManager: directory iteration error: " << lEc.message());
            break;
        }

        // We only care about .bpf.o files at the top level of the directory.
        if (!lEntry.is_regular_file() || lEntry.path().extension() != ".o")
        {
            continue;
        }
        if (lEntry.path().stem().extension() != ".bpf")
        {
            continue;
        }

        Status lStLoad = loadOne(lEntry.path());
        if (!lStLoad.has_value())
        {
            // Log the error but continue loading other probes.
            LOG_WARN(g_logEbpf, "ProbeManager: failed to load "
                << lEntry.path().filename().string()
                << " — " << lStLoad.error().message());
            continue;
        }

        ++lILoaded;
        LOG_INFO(g_logEbpf, "ProbeManager: loaded " << lEntry.path().filename().string());
    }

    if (lILoaded == 0)
    {
        return std::unexpected(makeError(
            ErrorCode::NOT_FOUND,
            ErrorCategory::EBPF,
            std::format("No .bpf.o probes loaded from: {}", m_probeDir.string())
        ));
    }

    LOG_INFO(g_logEbpf, "ProbeManager: " << lILoaded << " probe(s) loaded successfully");
    return {};
}

// ----------------------------------------------------------------------------
// loadOne()
//
// Loads and attaches a single .bpf.o file:
//   1. bpf_object__open()   — parse ELF, validate BTF
//   2. bpf_object__load()   — JIT-compile, load maps/programs into kernel
//   3. bpf_object__find_map_by_name() — locate the shared ring buffer map
//   4. Attach each program to its USDT tracepoint via bpf_program__attach()
//
// The bpf_object* is stored in m_vLoadedObjects for cleanup in unloadAll().
// ----------------------------------------------------------------------------
Status ProbeManager::loadOne(const std::filesystem::path& aBpfObjPath) noexcept
{
    const std::string lSzPath = aBpfObjPath.string();

    // -----------------------------------------------------------------
    // Open the BPF ELF object. This does NOT load it into the kernel yet.
    // libbpf parses the BTF info, map definitions, and program sections.
    // -----------------------------------------------------------------
    DECLARE_LIBBPF_OPTS(bpf_object_open_opts, lOpenOpts);
    bpf_object* lPObj = bpf_object__open_file(lSzPath.c_str(), &lOpenOpts);
    if (!lPObj || libbpf_get_error(lPObj))
    {
        return std::unexpected(makeError(
            ErrorCode::SYSCALL_FAILED,
            ErrorCategory::EBPF,
            std::format("bpf_object__open_file failed for: {}", lSzPath)
        ));
    }

    // -----------------------------------------------------------------
    // Load all programs and maps from this object into the kernel.
    // The verifier runs here — if the BPF bytecode is invalid, this fails.
    // -----------------------------------------------------------------
    int lIErr = bpf_object__load(lPObj);
    if (lIErr != 0)
    {
        bpf_object__close(lPObj);
        return std::unexpected(makeError(
            ErrorCode::SYSCALL_FAILED,
            ErrorCategory::EBPF,
            std::format("bpf_object__load failed (errno {}): {}", -lIErr, lSzPath)
        ));
    }

    // -----------------------------------------------------------------
    // Find the shared ring buffer map by name.
    // We only record the first one we encounter; Sprint 1 uses one shared
    // ring buffer across all probes. Sprint 2 will introduce per-purpose
    // buffers (security ring, telemetry ring).
    // -----------------------------------------------------------------
    if (m_iRingBufMapFd < 0)
    {
        struct bpf_map* lPMap = bpf_object__find_map_by_name(lPObj, k_szRingBufMapName);
        if (lPMap)
        {
            m_iRingBufMapFd = bpf_map__fd(lPMap);
            LOG_INFO(g_logEbpf, "ProbeManager: ring buffer map fd = " << m_iRingBufMapFd);
        }
    }

    // -----------------------------------------------------------------
    // Attach all programs in this object to their respective tracepoints.
    // bpf_program__attach() reads the SEC() annotation (e.g. "usdt/astra:task_spawn")
    // and resolves the correct attachment mechanism automatically.
    // -----------------------------------------------------------------
    struct bpf_program* lPProg = nullptr;
    bpf_object__for_each_program(lPProg, lPObj)
    {
        struct bpf_link* lPLink = bpf_program__attach(lPProg);
        if (!lPLink || libbpf_get_error(lPLink))
        {
            LOG_WARN(g_logEbpf, "ProbeManager: failed to attach program "
                << bpf_program__name(lPProg));
            // Non-fatal: continue with other programs in this object
            continue;
        }
        LOG_INFO(g_logEbpf, "ProbeManager: attached " << bpf_program__name(lPProg));
    }

    // Take ownership of the object pointer
    m_vLoadedObjects.push_back(lPObj);
    return {};
}

// ----------------------------------------------------------------------------
// unloadAll() — closes every loaded BPF object.
// bpf_object__close() implicitly detaches all linked programs and
// removes the maps from the kernel when the last reference drops.
// ----------------------------------------------------------------------------
void ProbeManager::unloadAll() noexcept
{
    for (bpf_object* lPObj : m_vLoadedObjects)
    {
        if (lPObj)
        {
            bpf_object__close(lPObj);
        }
    }
    m_vLoadedObjects.clear();
    m_iRingBufMapFd = -1;

    LOG_INFO(g_logEbpf, "ProbeManager: all probes unloaded");
}

int ProbeManager::ringBufferMapFd() const noexcept
{
    return m_iRingBufMapFd;
}


// ============================================================================
// RingBufferPoller Implementation
// ============================================================================

RingBufferPoller::RingBufferPoller(int aRingBufMapFd) noexcept
    : m_iMapFd(aRingBufMapFd)
    , m_pRingBuf(nullptr)
    , m_iEpollFd(-1)
    , m_bRunning(false)
{
}

RingBufferPoller::~RingBufferPoller()
{
    // Ensure the poll loop is stopped before we destroy the ring buffer handle
    stop();

    if (m_pRingBuf)
    {
        ring_buffer__free(m_pRingBuf);
        m_pRingBuf = nullptr;
    }
    if (m_iEpollFd >= 0)
    {
        ::close(m_iEpollFd);
        m_iEpollFd = -1;
    }
}

// ----------------------------------------------------------------------------
// init()
//
// Creates the userspace ring buffer consumer and the epoll fd used to
// sleep-wait for events without busy-polling.
//
// HOW THE EPOLL INTEGRATION WORKS:
//   ring_buffer__new() returns a handle that internally wraps an epoll fd.
//   We obtain that fd via ring_buffer__epoll_fd() and register it with our
//   own outer epoll fd. This two-level epoll approach lets us add additional
//   event sources (e.g. stop pipe) in Sprint 2 without rearchitecting.
// ----------------------------------------------------------------------------
Status RingBufferPoller::init() noexcept
{
    if (m_iMapFd < 0)
    {
        return std::unexpected(makeError(
            ErrorCode::NOT_INITIALIZED,
            ErrorCategory::EBPF,
            "RingBufferPoller::init() called with invalid map fd"
        ));
    }

    // -----------------------------------------------------------------
    // Create the libbpf ring buffer consumer.
    // onSample() is our callback — called once per event.
    // 'this' is passed as the context pointer (void* aCtx).
    // -----------------------------------------------------------------
    m_pRingBuf = ring_buffer__new(m_iMapFd, &RingBufferPoller::onSample, this, nullptr);
    if (!m_pRingBuf)
    {
        return std::unexpected(makeError(
            ErrorCode::SYSCALL_FAILED,
            ErrorCategory::EBPF,
            std::format("ring_buffer__new failed (errno {}): {}", errno, std::strerror(errno))
        ));
    }

    // -----------------------------------------------------------------
    // Create our outer epoll fd.
    // We register the ring buffer's internal epoll fd as a member so that
    // epoll_wait on m_iEpollFd wakes up when new ring buffer events arrive.
    // -----------------------------------------------------------------
    m_iEpollFd = ::epoll_create1(EPOLL_CLOEXEC);
    if (m_iEpollFd < 0)
    {
        return std::unexpected(makeError(
            ErrorCode::SYSCALL_FAILED,
            ErrorCategory::EBPF,
            std::format("epoll_create1 failed: {}", std::strerror(errno))
        ));
    }

    struct epoll_event lEv{};
    lEv.events  = EPOLLIN;
    lEv.data.fd = ring_buffer__epoll_fd(m_pRingBuf);

    if (::epoll_ctl(m_iEpollFd, EPOLL_CTL_ADD, lEv.data.fd, &lEv) != 0)
    {
        return std::unexpected(makeError(
            ErrorCode::SYSCALL_FAILED,
            ErrorCategory::EBPF,
            std::format("epoll_ctl EPOLL_CTL_ADD failed: {}", std::strerror(errno))
        ));
    }

    LOG_INFO(g_logEbpf, "RingBufferPoller: initialized (epoll_fd=" << m_iEpollFd << ")");
    return {};
}

// ----------------------------------------------------------------------------
// pollLoop()
//
// The main event ingestion loop. Runs on the dedicated ingestion thread.
//
// LOOP INVARIANT:
//   The loop exits only when m_bRunning is false. stop() sets this atomically.
//   After the loop, the thread function returns, allowing join() to complete.
//
// FLOW PER ITERATION:
//   1. epoll_wait() — sleep until ring buffer has data or timeout fires.
//   2. ring_buffer__consume() — drain all available events, calling onSample()
//      for each one. Returns the count of events consumed or a negative errno.
// ----------------------------------------------------------------------------
void RingBufferPoller::pollLoop() noexcept
{
    LOG_INFO(g_logEbpf, "RingBufferPoller: ingestion thread started");

    struct epoll_event lEvents[k_iMaxEpollEvents];

    while (m_bRunning.load(std::memory_order_acquire))
    {
        // -----------------------------------------------------------------
        // Sleep until we have events or the timeout expires.
        // The timeout lets us periodically re-check m_bRunning so stop()
        // can wake us up within k_iEpollTimeoutMs milliseconds.
        // -----------------------------------------------------------------
        int lINReady = ::epoll_wait(
            m_iEpollFd,
            lEvents,
            k_iMaxEpollEvents,
            k_iEpollTimeoutMs
        );

        if (lINReady < 0)
        {
            if (errno == EINTR)
            {
                // Interrupted by signal — loop back and check m_bRunning
                continue;
            }
            LOG_ERROR(g_logEbpf, "RingBufferPoller: epoll_wait error: " << std::strerror(errno));
            break;
        }

        if (lINReady == 0)
        {
            // Timeout — no events, just re-check m_bRunning
            continue;
        }

        // -----------------------------------------------------------------
        // Events are ready. ring_buffer__consume() drains all of them,
        // calling our onSample() callback once for each event.
        // -----------------------------------------------------------------
        int lIConsumed = ring_buffer__consume(m_pRingBuf);
        if (lIConsumed < 0)
        {
            LOG_WARN(g_logEbpf, "RingBufferPoller: ring_buffer__consume error: " << lIConsumed);
        }
    }

    LOG_INFO(g_logEbpf, "RingBufferPoller: ingestion thread exiting");
}

// ----------------------------------------------------------------------------
// start() — arm the running flag before the poll thread is launched.
// Only sets m_bRunning = true; does NOT start a thread.
// ----------------------------------------------------------------------------
void RingBufferPoller::start() noexcept
{
    m_bRunning.store(true, std::memory_order_release);
}

// ----------------------------------------------------------------------------
// stop() — signals the poll loop to exit on its next iteration.
// Sets m_bRunning = false atomically. The thread wakes within
// k_iEpollTimeoutMs milliseconds and exits pollLoop().
// ----------------------------------------------------------------------------
void RingBufferPoller::stop() noexcept
{
    m_bRunning.store(false, std::memory_order_release);
}

// ----------------------------------------------------------------------------
// isRunning() — safe public read of the running flag.
// ----------------------------------------------------------------------------
bool RingBufferPoller::isRunning() const noexcept
{
    return m_bRunning.load(std::memory_order_acquire);
}

// ----------------------------------------------------------------------------
// onSample() — static callback called by ring_buffer__consume() for each event.
//
// CONTRACT WITH libbpf:
//   aCtx      — the 'this' pointer we registered in ring_buffer__new()
//   aData     — pointer to the raw event bytes in the ring buffer
//   aDataSize — total size of this event in bytes
//
// We cast aData to EbpfEventHeader* and validate the size before printing.
// All multi-byte fields are little-endian (matching x86 BPF output).
// ----------------------------------------------------------------------------
int RingBufferPoller::onSample(void* aCtx, void* aData, SizeT aDataSize) noexcept
{
    (void)aCtx;  // Context not used in Sprint 1; retained for Sprint 2 routing

    // Minimum event must contain a full header
    if (aDataSize < sizeof(EbpfEventHeader))
    {
        std::fprintf(stdout,
            "[M-09][ebpf] WARN: undersized event (%zu bytes), skipping\n",
            aDataSize);
        return 0;
    }

    // Reinterpret the raw bytes as our strongly-typed header.
    // SAFETY: the BPF program guarantees alignment via __attribute__((packed))
    // and the ring buffer always provides at least event_size bytes.
    const auto* lPHdr = static_cast<const EbpfEventHeader*>(aData);

    // Print the deserialized event header to stdout.
    // In Sprint 1 this is the "ingestion complete" proof-of-concept output.
    // Sprint 2 will route events to the structured telemetry bus instead.
    std::fprintf(stdout,
        "[M-09][ebpf] EVENT "
        "ts=%-20llu type=%-4u pid=%-8u flags=0x%04x\n",
        static_cast<unsigned long long>(lPHdr->m_uTimestampNs),
        static_cast<unsigned int>(lPHdr->m_uEventType),
        static_cast<unsigned int>(lPHdr->m_uSourcePid),
        static_cast<unsigned int>(lPHdr->m_uFlags)
    );
    std::fflush(stdout);

    return 0;
}


// ============================================================================
// EbpfService Implementation
// ============================================================================

EbpfService::EbpfService(std::filesystem::path aProbeDir) noexcept
    : m_probeManager(std::move(aProbeDir))
    , m_pPoller(nullptr)
    , m_bInitialised(false)
    , m_bStarted(false)
{
}

EbpfService::~EbpfService()
{
    // Defensive: ensure we stop cleanly if onStop() was never called
    if (m_bStarted)
    {
        (void)onStop();
    }
}

std::string_view EbpfService::name() const noexcept
{
    return "ebpf-observability";
}

ModuleId EbpfService::moduleId() const noexcept
{
    return ModuleId::EBPF;
}

// ----------------------------------------------------------------------------
// onInit()
//
// Called by the Service Registry on the main thread before onStart().
// We do ALL blocking kernel work here (loading BPF objects) so that
// onStart() can return quickly.
//
// STEPS:
//   1. Guard against double-init.
//   2. Initialize the module logger.
//   3. ProbeManager::loadAll() — scan the probe dir and JIT-load probes.
//   4. Instantiate RingBufferPoller with the ring buffer map fd.
//   5. RingBufferPoller::init() — set up the epoll fd.
// ----------------------------------------------------------------------------
Status EbpfService::onInit()
{
    if (m_bInitialised)
    {
        return std::unexpected(makeError(
            ErrorCode::ALREADY_INITIALIZED,
            ErrorCategory::EBPF,
            "EbpfService::onInit() called twice"
        ));
    }

    // Initialize the file-backed logger for this module.
    // Falls back to stderr if the file cannot be opened.
    g_logEbpf.initialise("ebpf", "logs/ebpf.log");
    LOG_INFO(g_logEbpf, "EbpfService: onInit() starting");

    // -----------------------------------------------------------------
    // Load all BPF probes from the configured probe directory.
    // This is the most likely failure point — requires CAP_BPF or root.
    // -----------------------------------------------------------------
    Status lStLoad = m_probeManager.loadAll();
    if (!lStLoad.has_value())
    {
        LOG_ERROR(g_logEbpf, "EbpfService: probe load failed — "
            << lStLoad.error().message());
        return lStLoad;
    }

    int lIRingBufFd = m_probeManager.ringBufferMapFd();
    if (lIRingBufFd < 0)
    {
        return std::unexpected(makeError(
            ErrorCode::NOT_FOUND,
            ErrorCategory::EBPF,
            "EbpfService: no ring buffer map found after loading probes"
        ));
    }

    // -----------------------------------------------------------------
    // Create and initialize the ring buffer poller.
    // The poller sets up its internal epoll fd here; the poll loop itself
    // starts in onStart().
    // -----------------------------------------------------------------
    m_pPoller = std::make_unique<RingBufferPoller>(lIRingBufFd);
    Status lStPoller = m_pPoller->init();
    if (!lStPoller.has_value())
    {
        LOG_ERROR(g_logEbpf, "EbpfService: RingBufferPoller init failed — "
            << lStPoller.error().message());
        return lStPoller;
    }

    m_bInitialised = true;
    LOG_INFO(g_logEbpf, "EbpfService: onInit() complete");
    return {};
}

// ----------------------------------------------------------------------------
// onStart()
//
// Called by the Service Registry when the runtime transitions to RUNNING.
// We keep this as brief as possible: just launch the ingestion thread
// and return. The thread runs independently until onStop() is called.
//
// TODO(Sprint 2): Replace std::thread with EbpfThreadPool task submission.
// ----------------------------------------------------------------------------
Status EbpfService::onStart()
{
    if (!m_bInitialised)
    {
        return std::unexpected(makeError(
            ErrorCode::NOT_INITIALIZED,
            ErrorCategory::EBPF,
            "EbpfService::onStart() called before onInit()"
        ));
    }
    if (m_bStarted)
    {
        return std::unexpected(makeError(
            ErrorCode::ALREADY_INITIALIZED,
            ErrorCategory::EBPF,
            "EbpfService::onStart() called twice"
        ));
    }

    LOG_INFO(g_logEbpf, "EbpfService: launching ingestion thread");

    // Signal the poller that it should keep running before we launch the thread.
    m_pPoller->start();

    // Launch the dedicated ingestion thread.
    // The thread calls RingBufferPoller::pollLoop() which blocks on epoll_wait.
    // TODO(Sprint 2): submit as EbpfThreadPool::submit([this]{ m_pPoller->pollLoop(); });
    m_ingestionThread = std::thread([this]
    {
        m_pPoller->pollLoop();
    });

    m_bStarted = true;
    LOG_INFO(g_logEbpf, "EbpfService: onStart() complete — ingestion thread running");
    return {};
}

// ----------------------------------------------------------------------------
// onStop()
//
// Called during orderly shutdown. Signals the poll loop to stop and waits
// for the ingestion thread to exit cleanly before releasing resources.
// ----------------------------------------------------------------------------
Status EbpfService::onStop()
{
    LOG_INFO(g_logEbpf, "EbpfService: onStop() — signaling ingestion thread");

    if (m_pPoller)
    {
        m_pPoller->stop();
    }

    if (m_ingestionThread.joinable())
    {
        m_ingestionThread.join();
        LOG_INFO(g_logEbpf, "EbpfService: ingestion thread joined");
    }

    // Detach all BPF probes and release the kernel resources
    m_probeManager.unloadAll();

    m_bStarted     = false;
    m_bInitialised = false;

    LOG_INFO(g_logEbpf, "EbpfService: onStop() complete");
    return {};
}

// ----------------------------------------------------------------------------
// isHealthy()
//
// Called periodically by M-01. We are healthy if we have loaded at least
// one probe, the poller is up, and the ingestion thread is still running.
// ----------------------------------------------------------------------------
bool EbpfService::isHealthy() const noexcept
{
    if (!m_bInitialised || !m_bStarted) return false;
    if (!m_pPoller)                     return false;
    return m_pPoller->isRunning();
}

} // namespace ebpf
} // namespace astra
