// ============================================================================
// Astra Runtime - M-09 eBPF Observability Microservice
// include/astra/ebpf/ebpf_service.h
//
// Public interface for the eBPF Observability module. This header defines
// all types and classes that are visible to the rest of the Astra Runtime.
//
// ARCHITECTURE OVERVIEW (Sprint 1):
//
//   ┌─────────────────────────────────────────────────────────────────┐
//   │                    EbpfService (IService)                       │
//   │  ┌──────────────────────┐   ┌──────────────────────────────┐   │
//   │  │    ProbeManager      │   │     RingBufferPoller         │   │
//   │  │                      │   │                              │   │
//   │  │ - Loads .bpf.o files │   │ - Owns epoll fd              │   │
//   │  │   from probe dir     │   │ - Runs on dedicated thread   │   │
//   │  │ - Attaches probes    │   │ - Deserializes EbpfEventHdr  │   │
//   │  │   idempotently       │   │ - Prints events to stdout    │   │
//   │  └──────────────────────┘   └──────────────────────────────┘   │
//   └─────────────────────────────────────────────────────────────────┘
//
//   Kernel side:                        User side:
//   task_spawn.bpf.o  ──ring-buffer──▶  RingBufferPoller::pollLoop()
//   (USDT probe)                        (epoll_wait, sleeping when idle)
//
// THREADING MODEL:
//   onInit()  — runs on the Service Registry thread (no blocking allowed)
//   onStart() — launches the ingestion thread and returns immediately
//   pollLoop()— runs forever on a dedicated std::thread until m_bRunning=false
//
//   TODO(Sprint 2): Migrate pollLoop() from raw std::thread to EbpfThreadPool.
//
// ERROR HANDLING:
//   All methods return astra::Status or astra::Result<T>. Exceptions are
//   never thrown. Linux syscall failures are wrapped in makeError().
// ============================================================================
#ifndef ASTRA_EBPF_EBPF_SERVICE_H
#define ASTRA_EBPF_EBPF_SERVICE_H

#include <astra/common/types.h>
#include <astra/common/result.h>
#include <astra/core/service.h>

#include <atomic>
#include <filesystem>
#include <string>
#include <thread>
#include <vector>

// Forward-declare the libbpf struct so consumers of this header do not
// need to pull in <bpf/libbpf.h> transitively.
struct bpf_object;
struct ring_buffer;

namespace astra
{
namespace ebpf
{

// ============================================================================
// EbpfEventHeader
//
// Every event written by a kernel BPF probe into the shared ring buffer
// begins with this exact header layout. The BPF C struct in
// src/ebpf/probes/task_spawn.bpf.c MUST match this layout byte-for-byte.
//
// Layout (total: 16 bytes packed):
//   Offset  Size  Field
//   ------  ----  -----
//   0       8     timestamp     — CLOCK_MONOTONIC_COARSE nanoseconds
//   8       2     event_type    — discriminates the event kind (see EbpfEventType)
//   10      4     source_pid    — kernel PID that triggered the event
//   14      2     flags         — reserved bitmask for future use; must be 0 in Sprint 1
//
// ALIGNMENT NOTE:
//   We use __attribute__((packed)) to guarantee the BPF verifier and the
//   userspace C++ struct see the identical memory layout regardless of the
//   compiler's default alignment rules.
// ============================================================================
struct __attribute__((packed)) EbpfEventHeader
{
    U64 m_uTimestampNs;   // CLOCK_MONOTONIC_COARSE nanoseconds since boot
    U16 m_uEventType;     // discriminated union tag — see EbpfEventType below
    U32 m_uSourcePid;     // kernel PID (task_struct->pid) that fired the probe
    U16 m_uFlags;         // bitmask — reserved; must be 0 in Sprint 1
};

static_assert(sizeof(EbpfEventHeader) == 16,
    "EbpfEventHeader must be exactly 16 bytes — BPF struct must match");

// ----------------------------------------------------------------------------
// EbpfEventType — discriminates the type of event in the ring buffer.
// Values must stay in sync with the #define constants in task_spawn.bpf.c.
// ----------------------------------------------------------------------------
enum class EbpfEventType : U16
{
    UNKNOWN      = 0,
    TASK_SPAWN   = 1,   // process/task spawned (task_spawn USDT tracepoint)
    TASK_EXIT    = 2,   // process/task exited  (task_exit USDT tracepoint)
    SERVICE_EVT  = 3,   // service lifecycle event (service_event USDT)
};

// ============================================================================
// ProbeManager
//
// Responsible for the full lifecycle of BPF probe objects:
//   1. Scanning a flat directory for pre-compiled .bpf.o files.
//   2. Opening each object with bpf_object__open().
//   3. Loading (JIT-compiling) the programs into the kernel.
//   4. Attaching them to the correct USDT tracepoints.
//
// Attachment is idempotent: probes already loaded are detected by name
// and skipped, preventing double-attachment on service restart.
// ============================================================================
class ProbeManager
{
public:
    // -------------------------------------------------------------------------
    // Construct with the directory path from which to load .bpf.o files.
    // The directory is scanned lazily at loadAll() time.
    // -------------------------------------------------------------------------
    explicit ProbeManager(std::filesystem::path aProbeDir) noexcept;
    ~ProbeManager();

    // Non-copyable: owns kernel file descriptors
    ProbeManager(const ProbeManager&)            = delete;
    ProbeManager& operator=(const ProbeManager&) = delete;

    // -------------------------------------------------------------------------
    // loadAll() — scan aProbeDir, load every .bpf.o, attach its programs.
    //
    // Returns OK on success, or the first error encountered.
    // Already-attached probes are skipped (idempotent).
    // -------------------------------------------------------------------------
    Status loadAll() noexcept;

    // -------------------------------------------------------------------------
    // unloadAll() — detach and destroy all loaded BPF objects.
    // Called automatically by the destructor.
    // -------------------------------------------------------------------------
    void unloadAll() noexcept;

    // -------------------------------------------------------------------------
    // Returns the BPF map file descriptor for the shared ring buffer.
    // Returns -1 if the map has not been found yet.
    // -------------------------------------------------------------------------
    [[nodiscard]] int ringBufferMapFd() const noexcept;

private:
    // -------------------------------------------------------------------------
    // loadOne() — load and attach a single .bpf.o file.
    // -------------------------------------------------------------------------
    Status loadOne(const std::filesystem::path& aBpfObjPath) noexcept;

    // Flat list of successfully loaded BPF objects. We hold the pointers
    // so we can call bpf_object__close() during unloadAll().
    std::vector<bpf_object*> m_vLoadedObjects;

    // Flat list of attached BPF program links. Destroyed in unloadAll()
    // to cleanly detach probes before closing the objects.
    std::vector<struct bpf_link*> m_vAttachedLinks;

    // Root directory to scan for .bpf.o files
    std::filesystem::path m_probeDir;

    // File descriptor of the ring_buffer BPF map, set after loadAll()
    int m_iRingBufMapFd;
};


// ============================================================================
// RingBufferPoller
//
// Owns the userspace side of the BPF ring buffer. Wraps libbpf's
// ring_buffer__new() and drives it with an epoll wait loop.
//
// The polling loop:
//   - Uses epoll_wait() so the thread sleeps with zero CPU when the ring
//     buffer is empty (no busy-polling).
//   - Wakes instantly when the kernel submits a new event.
//   - Deserializes the raw bytes against EbpfEventHeader.
//   - In Sprint 1, events are printed to stdout for easy verification.
//
// The loop runs until m_bRunning is set to false (by EbpfService::onStop()).
// ============================================================================
class RingBufferPoller
{
public:
    // -------------------------------------------------------------------------
    // Construct with the BPF ring buffer map file descriptor.
    // The fd is obtained from ProbeManager::ringBufferMapFd().
    // -------------------------------------------------------------------------
    explicit RingBufferPoller(int aRingBufMapFd) noexcept;
    ~RingBufferPoller();

    // Non-copyable: owns the ring_buffer* handle
    RingBufferPoller(const RingBufferPoller&)            = delete;
    RingBufferPoller& operator=(const RingBufferPoller&) = delete;

    // -------------------------------------------------------------------------
    // init() — set up the ring buffer consumer and epoll fd.
    // Must be called before pollLoop().
    // -------------------------------------------------------------------------
    Status init() noexcept;

    // -------------------------------------------------------------------------
    // pollLoop() — blocking event ingestion loop.
    //
    // Runs until stop() is called from another thread. Designed to be
    // launched as the body of a dedicated std::thread.
    // -------------------------------------------------------------------------
    void pollLoop() noexcept;

    // -------------------------------------------------------------------------
    // start() — arm the running flag before the poll thread is launched.
    // Must be called from EbpfService::onStart() before spawning the thread.
    // -------------------------------------------------------------------------
    void start() noexcept;

    // -------------------------------------------------------------------------
    // stop() — signal the poll loop to exit.
    // Thread-safe: sets the atomic m_bRunning flag.
    // -------------------------------------------------------------------------
    void stop() noexcept;

    // -------------------------------------------------------------------------
    // isRunning() — returns true while the poll loop is active.
    // Used by EbpfService::isHealthy().
    // -------------------------------------------------------------------------
    [[nodiscard]] bool isRunning() const noexcept;

private:
    // -------------------------------------------------------------------------
    // onSample() — libbpf callback, called for each event in the ring buffer.
    // Casts the raw data to EbpfEventHeader and prints it.
    // -------------------------------------------------------------------------
    static int onSample(void* aCtx, void* aData, SizeT aDataSize) noexcept;

    // BPF ring buffer map fd provided by ProbeManager
    int             m_iMapFd;

    // libbpf ring buffer consumer handle
    ring_buffer*    m_pRingBuf;

    // epoll fd used to sleep the thread when the ring buffer is idle
    int             m_iEpollFd;

    // Atomic flag: the poll loop spins while true
    std::atomic<bool> m_bRunning;
};


// ============================================================================
// EbpfService
//
// The IService implementation that wires M-09 into the M-01 Service Registry.
//
// Lifecycle:
//   onInit()  — ProbeManager::loadAll()   (no threads started yet)
//   onStart() — RingBufferPoller::init()  + launch m_ingestionThread
//   onStop()  — RingBufferPoller::stop()  + join m_ingestionThread
//               + ProbeManager::unloadAll()
// ============================================================================
class EbpfService : public astra::core::IService
{
public:
    // -------------------------------------------------------------------------
    // Construct with the directory that holds pre-compiled .bpf.o files.
    // The path is passed via CMake's generated-probes output directory.
    // -------------------------------------------------------------------------
    explicit EbpfService(std::filesystem::path aProbeDir) noexcept;
    ~EbpfService() override;

    // --- IService interface ---------------------------------------------------
    [[nodiscard]] std::string_view name()     const noexcept override;
    [[nodiscard]] ModuleId         moduleId() const noexcept override;
    Status                         onInit()         override;
    Status                         onStart()        override;
    Status                         onStop()         override;
    [[nodiscard]] bool             isHealthy() const noexcept override;

private:
    // ProbeManager handles BPF object loading and USDT attachment
    ProbeManager        m_probeManager;

    // RingBufferPoller handles the epoll-based event ingestion loop;
    // allocated after ProbeManager::loadAll() succeeds in onInit()
    std::unique_ptr<RingBufferPoller> m_pPoller;

    // Dedicated background thread for the ring buffer ingestion loop.
    // TODO(Sprint 2): Replace with EbpfThreadPool — see design doc §4.2.
    std::thread         m_ingestionThread;

    // Guards against double-init / double-start
    bool m_bInitialised;
    bool m_bStarted;
};

} // namespace ebpf
} // namespace astra

#endif // ASTRA_EBPF_EBPF_SERVICE_H
