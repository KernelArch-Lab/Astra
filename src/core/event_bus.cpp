// ============================================================================
// Astra Runtime - Event Bus Implementation (M-01)
// src/core/event_bus.cpp
// ============================================================================

#include <astra/core/event_bus.h>
#include <astra/asm_core/asm_core.h>
#include <astra/common/log.h>

#include <chrono>
#include <cstring>
#include <new>

static const char* LOG_TAG = "event_bus";

namespace astra
{
namespace core
{

// ============================================================================
// Construction / Destruction
// ============================================================================

EventBus::EventBus()
    : m_pRingBuffer(nullptr)
    , m_uRingSize(0)
    , m_uRingMask(0)
    , m_uWriteHead(0)
    , m_uReadHead(0)
    , m_uSubscriberCount(0)
    , m_uTotalPublished(0)
    , m_uTotalDropped(0)
    , m_uSequenceCounter(0)
    , m_bInitialised(false)
{
    std::memset(m_arrSubscribers, 0, sizeof(m_arrSubscribers));
}

EventBus::~EventBus()
{
    if (m_bInitialised)
    {
        shutdown();
    }
}


// ============================================================================
// init
// ============================================================================

Status EventBus::init(U32 aURingSize)
{
    if (m_bInitialised)
    {
        return std::unexpected(makeError(
            ErrorCode::ALREADY_INITIALIZED,
            ErrorCategory::CORE,
            "EventBus already initialised"
        ));
    }

    if (aURingSize == 0)
    {
        aURingSize = DEFAULT_RING_SIZE;
    }

    // Ring size must be a power of 2 for fast modulo (bitwise AND)
    // Round up to next power of 2 if needed
    U32 lUSize = 1;
    while (lUSize < aURingSize)
    {
        lUSize <<= 1;
    }
    aURingSize = lUSize;

    m_pRingBuffer = new (std::nothrow) Event[aURingSize];
    if (m_pRingBuffer == nullptr)
    {
        return std::unexpected(makeError(
            ErrorCode::OUT_OF_MEMORY,
            ErrorCategory::CORE,
            "Failed to allocate event ring buffer"
        ));
    }

    // Zero-initialise the ring
    for (U32 lUIdx = 0; lUIdx < aURingSize; ++lUIdx)
    {
        m_pRingBuffer[lUIdx] = Event::null();
    }

    m_uRingSize = aURingSize;
    m_uRingMask = aURingSize - 1;
    m_uWriteHead.store(0, std::memory_order_release);
    m_uReadHead = 0;
    m_uSubscriberCount = 0;
    m_uTotalPublished.store(0, std::memory_order_release);
    m_uTotalDropped.store(0, std::memory_order_release);
    m_uSequenceCounter.store(0, std::memory_order_release);
    m_bInitialised = true;

    ASTRA_LOG_INFO(LOG_TAG, "Event bus initialised: ring size %u (mask 0x%x)",
                   aURingSize, m_uRingMask);
    return {};
}


// ============================================================================
// shutdown
// ============================================================================

void EventBus::shutdown()
{
    if (!m_bInitialised)
    {
        return;
    }

    ASTRA_LOG_INFO(LOG_TAG, "Shutting down event bus (published=%llu dropped=%llu)",
                   static_cast<unsigned long long>(m_uTotalPublished.load()),
                   static_cast<unsigned long long>(m_uTotalDropped.load()));

    // Dispatch any remaining events
    dispatch();

    if (m_pRingBuffer != nullptr)
    {
        asm_secure_wipe(m_pRingBuffer, static_cast<size_t>(m_uRingSize) * sizeof(Event));
        delete[] m_pRingBuffer;
        m_pRingBuffer = nullptr;
    }

    m_uRingSize = 0;
    m_uSubscriberCount = 0;
    m_bInitialised = false;

    ASTRA_LOG_INFO(LOG_TAG, "Event bus shutdown complete");
}


// ============================================================================
// subscribe
// ============================================================================

Result<U32> EventBus::subscribe(
    EventType           aEFilter,
    EventHandler        aHandler,
    std::string_view    aSzSubscriberName)
{
    if (!m_bInitialised)
    {
        return std::unexpected(makeError(
            ErrorCode::NOT_INITIALIZED,
            ErrorCategory::CORE,
            "EventBus not initialised"
        ));
    }

    if (m_uSubscriberCount >= MAX_SUBSCRIBERS)
    {
        return std::unexpected(makeError(
            ErrorCode::RESOURCE_EXHAUSTED,
            ErrorCategory::CORE,
            "Maximum number of event subscribers reached"
        ));
    }

    U32 lUIdx = m_uSubscriberCount;
    m_arrSubscribers[lUIdx].m_eFilter = aEFilter;
    m_arrSubscribers[lUIdx].m_handler = std::move(aHandler);
    m_arrSubscribers[lUIdx].m_bActive = true;

    // Copy subscriber name (truncate if needed)
    std::memset(m_arrSubscribers[lUIdx].m_szName, 0, sizeof(m_arrSubscribers[lUIdx].m_szName));
    if (!aSzSubscriberName.empty())
    {
        size_t lULen = aSzSubscriberName.size();
        if (lULen >= sizeof(m_arrSubscribers[lUIdx].m_szName))
        {
            lULen = sizeof(m_arrSubscribers[lUIdx].m_szName) - 1;
        }
        std::memcpy(m_arrSubscribers[lUIdx].m_szName, aSzSubscriberName.data(), lULen);
    }

    ++m_uSubscriberCount;

    ASTRA_LOG_DEBUG(LOG_TAG, "Subscriber [%u] '%.*s' registered (filter=%u)",
                    lUIdx,
                    static_cast<int>(aSzSubscriberName.size()), aSzSubscriberName.data(),
                    static_cast<unsigned>(aEFilter));

    return lUIdx;
}


// ============================================================================
// publish - write an event to the ring buffer (thread-safe, lock-free)
// ============================================================================

bool EventBus::publish(const Event& aEvent)
{
    if (!m_bInitialised)
    {
        return false;
    }

    // Atomically claim a write slot
    U32 lUSlot = m_uWriteHead.fetch_add(1, std::memory_order_acq_rel) & m_uRingMask;

    // Check if we are overwriting an unread event (ring full)
    // This is a best-effort check; in high contention we accept drops.
    U32 lUCurrentRead = m_uReadHead;
    U32 lUCurrentWrite = m_uWriteHead.load(std::memory_order_acquire);
    U32 lUPending = lUCurrentWrite - lUCurrentRead;
    if (lUPending > m_uRingSize)
    {
        m_uTotalDropped.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    m_pRingBuffer[lUSlot] = aEvent;
    m_uTotalPublished.fetch_add(1, std::memory_order_relaxed);

    return true;
}


// ============================================================================
// publishEvent - convenience wrapper with auto-filled metadata
// ============================================================================

bool EventBus::publishEvent(EventType aEType, U16 aUSourceModuleId)
{
    Event lEvent = Event::null();
    lEvent.m_eType = aEType;
    lEvent.m_uSourceModuleId = aUSourceModuleId;
    lEvent.m_uSequenceNum = m_uSequenceCounter.fetch_add(1, std::memory_order_acq_rel);
    lEvent.m_uTimestampNs = nowNs();

    return publish(lEvent);
}


// ============================================================================
// dispatch - deliver pending events to subscribers (single-threaded)
// ============================================================================

U32 EventBus::dispatch()
{
    if (!m_bInitialised)
    {
        return 0;
    }

    U32 lUWriteHead = m_uWriteHead.load(std::memory_order_acquire);
    U32 lUDispatched = 0;

    while (m_uReadHead != lUWriteHead)
    {
        U32 lUSlot = m_uReadHead & m_uRingMask;
        const Event& lEvent = m_pRingBuffer[lUSlot];

        if (lEvent.m_eType != EventType::NONE)
        {
            // Deliver to all matching subscribers
            for (U32 lUIdx = 0; lUIdx < m_uSubscriberCount; ++lUIdx)
            {
                const Subscriber& lSub = m_arrSubscribers[lUIdx];
                if (lSub.m_bActive)
                {
                    // Filter match: NONE means "all events"
                    if (lSub.m_eFilter == EventType::NONE ||
                        lSub.m_eFilter == lEvent.m_eType)
                    {
                        lSub.m_handler(lEvent);
                    }
                }
            }

            ++lUDispatched;
        }

        ++m_uReadHead;
    }

    return lUDispatched;
}


// ============================================================================
// Diagnostics
// ============================================================================

U32 EventBus::pendingCount() const noexcept
{
    if (!m_bInitialised)
    {
        return 0;
    }

    U32 lUWrite = m_uWriteHead.load(std::memory_order_acquire);
    return lUWrite - m_uReadHead;
}

U64 EventBus::totalPublished() const noexcept
{
    return m_uTotalPublished.load(std::memory_order_acquire);
}

U64 EventBus::totalDropped() const noexcept
{
    return m_uTotalDropped.load(std::memory_order_acquire);
}


// ============================================================================
// Internal helpers
// ============================================================================

U64 EventBus::nowNs() noexcept
{
    auto lTimeNow = std::chrono::steady_clock::now();
    auto lNsSinceEpoch = std::chrono::duration_cast<std::chrono::nanoseconds>(
        lTimeNow.time_since_epoch()
    );
    return static_cast<U64>(lNsSinceEpoch.count());
}

} // namespace core
} // namespace astra
