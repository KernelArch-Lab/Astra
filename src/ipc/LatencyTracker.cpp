// ============================================================================
// Astra Runtime - M-03 IPC Sprint 13: Latency Histogram
// src/ipc/LatencyTracker.cpp
// ============================================================================

#include <astra/ipc/LatencyTracker.hpp>
#include <astra/common/log.h>

#include <cstdio>
#include <cstring>

#include <time.h>

namespace astra
{
namespace ipc
{

namespace
{

constexpr const char* LOG_TAG = "ipc_latency";

U64 nowNs() noexcept
{
    struct timespec ts;
#ifdef CLOCK_MONOTONIC_RAW
    ::clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
#else
    ::clock_gettime(CLOCK_MONOTONIC, &ts);
#endif
    return static_cast<U64>(ts.tv_sec) * 1'000'000'000ULL
         + static_cast<U64>(ts.tv_nsec);
}

} // namespace

// ===========================================================================
// LatencyHistogram
// ===========================================================================

U32 LatencyHistogram::bucketFor(U64 aLatencyNs) noexcept
{
    if (aLatencyNs == 0U)
        return 0U;
    // floor(log2(aLatencyNs)) via count-leading-zeros
    const U32 lUBit = 63U - static_cast<U32>(__builtin_clzll(aLatencyNs));
    return (lUBit < NUM_BUCKETS) ? lUBit : (NUM_BUCKETS - 1U);
}

void LatencyHistogram::record(U64 aLatencyNs) noexcept
{
    m_buckets[bucketFor(aLatencyNs)].fetch_add(1U, std::memory_order_relaxed);
    m_uTotalSamples.fetch_add(1U,          std::memory_order_relaxed);
    m_uTotalNs     .fetch_add(aLatencyNs,  std::memory_order_relaxed);
}

void LatencyHistogram::reset() noexcept
{
    for (auto& b : m_buckets)
        b.store(0U, std::memory_order_relaxed);
    m_uTotalSamples.store(0U, std::memory_order_relaxed);
    m_uTotalNs     .store(0U, std::memory_order_relaxed);
}

LatencyHistogram::Snapshot LatencyHistogram::snapshot() const noexcept
{
    Snapshot lSnap{};
    for (U32 i = 0U; i < NUM_BUCKETS; ++i)
        lSnap.m_counts[i] = m_buckets[i].load(std::memory_order_relaxed);
    lSnap.m_uTotalSamples = m_uTotalSamples.load(std::memory_order_relaxed);
    lSnap.m_uTotalNs      = m_uTotalNs     .load(std::memory_order_relaxed);
    return lSnap;
}

int LatencyHistogram::Snapshot::minBucket() const noexcept
{
    for (int i = 0; i < static_cast<int>(NUM_BUCKETS); ++i)
        if (m_counts[i] > 0U) return i;
    return -1;
}

int LatencyHistogram::Snapshot::maxBucket() const noexcept
{
    for (int i = static_cast<int>(NUM_BUCKETS) - 1; i >= 0; --i)
        if (m_counts[i] > 0U) return i;
    return -1;
}

int LatencyHistogram::Snapshot::medianBucket() const noexcept
{
    if (m_uTotalSamples == 0U) return -1;
    const U64 lUTarget = m_uTotalSamples / 2U + 1U;
    U64 lUAccum = 0U;
    for (int i = 0; i < static_cast<int>(NUM_BUCKETS); ++i)
    {
        lUAccum += m_counts[i];
        if (lUAccum >= lUTarget) return i;
    }
    return static_cast<int>(NUM_BUCKETS) - 1;
}

void LatencyHistogram::print() const noexcept
{
    const Snapshot lSnap = snapshot();
    std::printf("LatencyHistogram (n=%llu, total=%llu ns",
        static_cast<unsigned long long>(lSnap.m_uTotalSamples),
        static_cast<unsigned long long>(lSnap.m_uTotalNs));
    if (lSnap.m_uTotalSamples > 0U)
    {
        std::printf(", mean=%llu ns",
            static_cast<unsigned long long>(lSnap.m_uTotalNs / lSnap.m_uTotalSamples));
    }
    std::printf("):\n");

    const int lIMax = lSnap.maxBucket();
    for (int i = 0; i <= lIMax; ++i)
    {
        if (lSnap.m_counts[i] == 0U) continue;
        const U64 lULo = (i == 0) ? 0ULL : (1ULL << (i - 1));
        const U64 lUHi = (1ULL << i) - 1ULL;
        std::printf("  [%6llu-%6llu ns] : %llu\n",
            static_cast<unsigned long long>(lULo),
            static_cast<unsigned long long>(lUHi),
            static_cast<unsigned long long>(lSnap.m_counts[i]));
    }
}

// ===========================================================================
// LatencyTracker
// ===========================================================================

LatencyTracker::LatencyTracker(RingBuffer& aRing) noexcept
    : m_ring(aRing)
{
}

Result<void> LatencyTracker::write(const void* aData, U32 aPayloadLen) noexcept
{
    if (aPayloadLen == 0U || aPayloadLen > MAX_TRACKED_PAYLOAD)
    {
        return std::unexpected(makeError(
            ErrorCode::INVALID_ARGUMENT,
            ErrorCategory::IPC,
            "LatencyTracker::write: payload must be 1..MAX_TRACKED_PAYLOAD bytes"
        ));
    }

    // Combined buffer: [timestamp U64][payload aPayloadLen bytes]
    alignas(8) std::byte lBuf[sizeof(U64) + MAX_TRACKED_PAYLOAD];

    const U64 lUWriteNs = nowNs();
    std::memcpy(lBuf, &lUWriteNs, sizeof(U64));
    std::memcpy(lBuf + sizeof(U64), aData, aPayloadLen);

    const auto lResult = m_ring.write(lBuf, static_cast<U32>(sizeof(U64)) + aPayloadLen);

    ASTRA_LOG_TRACE(LOG_TAG, "write: stamped payload=%u bytes", aPayloadLen);

    return lResult;
}

Result<U32> LatencyTracker::read(void* aBuf, U32 aBufLen) noexcept
{
    // Peek at the total ring-payload size to bound-check before reading
    auto lPeek = m_ring.peekNextSize();
    if (!lPeek.has_value())
        return std::unexpected(lPeek.error());

    const U32 lUTotal = *lPeek;

    if (lUTotal < static_cast<U32>(sizeof(U64)))
    {
        return std::unexpected(makeError(
            ErrorCode::INVALID_ARGUMENT,
            ErrorCategory::IPC,
            "LatencyTracker::read: message too small to contain timestamp"
        ));
    }

    const U32 lUAppLen = lUTotal - static_cast<U32>(sizeof(U64));

    if (aBufLen < lUAppLen)
    {
        return std::unexpected(makeError(
            ErrorCode::RESOURCE_EXHAUSTED,
            ErrorCategory::IPC,
            "LatencyTracker::read: destination buffer too small for payload"
        ));
    }

    // Read [timestamp + payload] into a combined stack buffer
    alignas(8) std::byte lCombined[sizeof(U64) + MAX_TRACKED_PAYLOAD];
    auto lRd = m_ring.read(lCombined, static_cast<U32>(sizeof(lCombined)));
    if (!lRd.has_value())
        return std::unexpected(lRd.error());

    const U64 lUReadNs = nowNs();

    U64 lUWriteNs = 0U;
    std::memcpy(&lUWriteNs, lCombined, sizeof(U64));

    if (lUReadNs >= lUWriteNs)
        m_histogram.record(lUReadNs - lUWriteNs);

    std::memcpy(aBuf, lCombined + sizeof(U64), lUAppLen);

    ASTRA_LOG_TRACE(LOG_TAG,
        "read: latency=%llu ns payload=%u bytes",
        static_cast<unsigned long long>(lUReadNs - lUWriteNs),
        lUAppLen);

    return lUAppLen;
}

const LatencyHistogram& LatencyTracker::histogram() const noexcept
{
    return m_histogram;
}

LatencyHistogram& LatencyTracker::histogram() noexcept
{
    return m_histogram;
}

} // namespace ipc
} // namespace astra
