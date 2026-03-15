// ============================================================================
// Astra Runtime - Event Bus (M-01)
// include/astra/core/event_bus.h
//
// System-wide event notification mechanism. The event bus provides
// loose coupling between modules: publishers emit events without
// knowing who (if anyone) is listening, and subscribers receive
// events without knowing who published them.
//
// Design principles:
//   - Lock-free event dispatch for the common case (single publisher).
//   - Pre-allocated event queue (ring buffer, no heap alloc).
//   - Events are small, fixed-size value types (fit in a cache line).
//   - Subscribers registered at init time; no dynamic subscription
//     during the hot path.
//
// Integration points:
//   - M-02 (Isolation): listens for PROCESS_SPAWNED to apply isolation.
//   - M-03 (IPC): listens for SERVICE_REGISTERED to update routing.
//   - M-09 (eBPF): bridges events to kernel tracepoints.
//   - M-17 (Profiler): captures event throughput metrics.
// ============================================================================
#ifndef ASTRA_CORE_EVENT_BUS_H
#define ASTRA_CORE_EVENT_BUS_H

#include <astra/common/types.h>
#include <astra/common/result.h>

#include <array>
#include <atomic>
#include <functional>
#include <string_view>

namespace astra
{
namespace core
{

// -------------------------------------------------------------------------
// Event types - all system-wide events the bus can carry.
// Each event type has a fixed payload layout (no polymorphism).
// -------------------------------------------------------------------------
enum class EventType : U16
{
    NONE                    = 0,

    // Runtime lifecycle events (1-99)
    RUNTIME_INITIALIZING    = 1,
    RUNTIME_RUNNING         = 2,
    RUNTIME_SHUTTING_DOWN   = 3,
    RUNTIME_STOPPED         = 4,

    // Service lifecycle events (100-199)
    SERVICE_REGISTERED      = 100,
    SERVICE_STARTED         = 101,
    SERVICE_STOPPED         = 102,
    SERVICE_FAILED          = 103,
    SERVICE_UNREGISTERED    = 104,

    // Process lifecycle events (200-299)
    PROCESS_SPAWNED         = 200,
    PROCESS_EXITED          = 201,
    PROCESS_CRASHED         = 202,
    PROCESS_RESTARTED       = 203,

    // Capability events (300-399)
    CAPABILITY_CREATED      = 300,
    CAPABILITY_DERIVED      = 301,
    CAPABILITY_REVOKED      = 302,

    // Security events (400-499)
    SECURITY_ALERT          = 400,
    SECURITY_BREACH         = 401,
    CAPABILITY_VIOLATION    = 402,
    INTEGRITY_CHECK_FAILED  = 403,

    // IPC events (500-599)
    IPC_CHANNEL_CREATED     = 500,
    IPC_CHANNEL_CLOSED      = 501,
    IPC_MESSAGE_DROPPED     = 502,

    // Module-defined events start at 1000
    // Each module gets a 100-event range:
    //   M-02: 1000-1099, M-03: 1100-1199, etc.
    MODULE_EVENT_BASE       = 1000
};


// -------------------------------------------------------------------------
// Event - fixed-size event structure.
// Fits in one cache line (64 bytes) for minimal cache pollution.
// The payload is a union of typed fields for each event category.
// -------------------------------------------------------------------------
struct alignas(64) Event
{
    EventType   m_eType;
    U16         m_uSourceModuleId;  // ModuleId of the publisher
    U32         m_uSequenceNum;     // monotonically increasing per-bus
    U64         m_uTimestampNs;     // nanosecond timestamp

    // Payload: 40 bytes available for event-specific data.
    // Interpret based on m_eType.
    union Payload
    {
        // Service events
        struct
        {
            U32     m_uServiceId;
            U16     m_uModuleId;
            char    m_szName[26];
        } m_service;

        // Process events
        struct
        {
            U64     m_uProcessId;
            I32     m_iExitCode;
            U32     m_uRestartCount;
            char    m_szReason[20];
        } m_process;

        // Capability events
        struct
        {
            U64     m_uTokenIdHigh;
            U64     m_uTokenIdLow;
            U64     m_uOwnerId;
            U64     m_uPermissions;
            U64     m_uEpoch;
        } m_capability;

        // Security events
        struct
        {
            U64     m_uSourceProcessId;
            U32     m_uThreatLevel;     // 1-10 severity
            char    m_szDescription[24];
        } m_security;

        // Generic payload for module-defined events
        struct
        {
            U8      m_arrData[40];
        } m_raw;

    } m_payload;

    // Construct a null event
    static Event null() noexcept
    {
        Event lEvent{};
        lEvent.m_eType = EventType::NONE;
        lEvent.m_uSourceModuleId = 0;
        lEvent.m_uSequenceNum = 0;
        lEvent.m_uTimestampNs = 0;
        lEvent.m_payload = {};
        return lEvent;
    }
};

// Verify Event fits in a cache line
static_assert(sizeof(Event) == 64, "Event must be exactly 64 bytes (one cache line)");


// -------------------------------------------------------------------------
// EventHandler - callback type for event subscribers.
// Handlers MUST be fast and non-blocking. If a handler needs to do
// heavy work, it should enqueue the event internally and return.
// -------------------------------------------------------------------------
using EventHandler = std::function<void(const Event& aEvent)>;


// -------------------------------------------------------------------------
// EventBus - publish/subscribe event notification system.
//
// Thread safety:
//   - publish() is thread-safe (atomic sequence number, lock-free ring).
//   - subscribe() is NOT thread-safe (must be called during init only).
//   - dispatch() is called from the runtime's main loop thread.
//
// Architecture:
//   - Ring buffer of events (power-of-2 size for fast modulo).
//   - publish() writes to the ring and increments the write head.
//   - dispatch() reads from the ring and calls all matching handlers.
//   - If the ring fills up, oldest events are silently dropped (with
//     a counter increment for monitoring).
// -------------------------------------------------------------------------
class EventBus
{
public:
    static constexpr U32 DEFAULT_RING_SIZE = 1024;  // must be power of 2
    static constexpr U32 MAX_SUBSCRIBERS = 64;

    EventBus();
    ~EventBus();

    EventBus(const EventBus&) = delete;
    EventBus& operator=(const EventBus&) = delete;
    EventBus(EventBus&&) = delete;
    EventBus& operator=(EventBus&&) = delete;

    // Initialise the event bus with a pre-allocated ring buffer
    Status init(U32 aURingSize = DEFAULT_RING_SIZE);

    // Shutdown and flush remaining events
    void shutdown();

    // Subscribe to events of a specific type.
    // Must be called during init phase (before runtime enters RUNNING).
    // aEFilter = EventType::NONE means "subscribe to ALL events".
    Result<U32> subscribe(
        EventType       aEFilter,
        EventHandler    aHandler,
        std::string_view aSzSubscriberName = ""
    );

    // Publish an event to the bus. Thread-safe, lock-free.
    // Returns false if the ring buffer is full (event dropped).
    bool publish(const Event& aEvent);

    // Convenience: publish with auto-filled timestamp and sequence number.
    bool publishEvent(
        EventType   aEType,
        U16         aUSourceModuleId
    );

    // Dispatch all pending events to subscribers.
    // Called from the runtime's main loop. NOT thread-safe with itself.
    // Returns the number of events dispatched.
    U32 dispatch();

    // Diagnostics
    [[nodiscard]] U32 pendingCount() const noexcept;
    [[nodiscard]] U64 totalPublished() const noexcept;
    [[nodiscard]] U64 totalDropped() const noexcept;

private:
    struct Subscriber
    {
        EventType       m_eFilter;
        EventHandler    m_handler;
        char            m_szName[32];
        bool            m_bActive;
    };

    // Ring buffer
    Event*                  m_pRingBuffer;
    U32                     m_uRingSize;
    U32                     m_uRingMask;    // ringSize - 1, for fast modulo
    std::atomic<U32>        m_uWriteHead;
    U32                     m_uReadHead;    // only accessed from dispatch thread

    // Subscribers (fixed array, no dynamic allocation)
    Subscriber              m_arrSubscribers[MAX_SUBSCRIBERS];
    U32                     m_uSubscriberCount;

    // Diagnostics
    std::atomic<U64>        m_uTotalPublished;
    std::atomic<U64>        m_uTotalDropped;
    std::atomic<U32>        m_uSequenceCounter;

    bool                    m_bInitialised;

    // Get current timestamp in nanoseconds
    static U64 nowNs() noexcept;
};

} // namespace core
} // namespace astra

#endif // ASTRA_CORE_EVENT_BUS_H
