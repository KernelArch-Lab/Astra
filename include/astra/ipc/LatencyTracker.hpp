// ============================================================================
// Astra Runtime - M-03 IPC Sprint 13: Latency Histogram
// include/astra/ipc/LatencyTracker.hpp
//
// Two components:
//
//   LatencyHistogram — lock-free 64-bucket power-of-two histogram.
//     Bucket i holds the count of samples whose latency falls in
//     [2^(i-1), 2^i) nanoseconds (bucket 0 catches 0 ns).
//     All operations are lock-free: record() is a single fetch_add;
//     snapshot() reads each counter with a relaxed load.
//
//   LatencyTracker — wraps a RingBuffer and adds write-to-read latency
//     measurement.  The write timestamp is embedded as an 8-byte prefix
//     in the ring payload; the reader strips it and records the delta in
//     the internal LatencyHistogram.  This is transparent to the caller:
//     write(data, N) puts N bytes; read(buf, N) returns N bytes.
//
//     Wire format in the ring:
//       [MessageHeader 8B | m_uPayloadBytes = sizeof(U64) + appLen]
//       [WriteTimestampNs  8B]
//       [App Payload       N B]
//
//     Constraint: max tracked payload = 4096 bytes (stack allocation).
//     LatencyTracker is designed for monitoring — not the hot data path.
// ============================================================================
#ifndef ASTRA_IPC_LATENCY_TRACKER_HPP
#define ASTRA_IPC_LATENCY_TRACKER_HPP

#include <astra/common/result.h>
#include <astra/ipc/RingBuffer.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>

namespace astra
{
namespace ipc
{

// ---------------------------------------------------------------------------
// LatencyHistogram
// ---------------------------------------------------------------------------
class LatencyHistogram
{
public:
    static constexpr U32 NUM_BUCKETS = 64U;

    // Record one latency sample (nanoseconds).
    void record(U64 aLatencyNs) noexcept;

    // Reset all counters to zero.
    void reset() noexcept;

    // ---------------------------------------------------------------------------
    // Snapshot — consistent read of all counters.
    // ---------------------------------------------------------------------------
    struct Snapshot
    {
        U64 m_counts[NUM_BUCKETS] {};
        U64 m_uTotalSamples = 0U;
        U64 m_uTotalNs      = 0U;    // sum of all recorded latencies

        // Lowest bucket index that has at least one sample (-1 if empty).
        [[nodiscard]] int minBucket() const noexcept;

        // Highest bucket index that has at least one sample (-1 if empty).
        [[nodiscard]] int maxBucket() const noexcept;

        // Approximate median bucket (the bucket that contains the 50th percentile).
        [[nodiscard]] int medianBucket() const noexcept;
    };

    [[nodiscard]] Snapshot snapshot() const noexcept;

    // Print a compact histogram to stdout (for debugging / tests).
    void print() const noexcept;

private:
    // Bucket index for a latency value: floor(log2(ns)), clamped to [0, 63].
    [[nodiscard]] static U32 bucketFor(U64 aLatencyNs) noexcept;

    std::atomic<U64> m_buckets[NUM_BUCKETS] {};
    std::atomic<U64> m_uTotalSamples {0U};
    std::atomic<U64> m_uTotalNs      {0U};
};

// ---------------------------------------------------------------------------
// LatencyTracker
// ---------------------------------------------------------------------------
class LatencyTracker
{
public:
    static constexpr U32 MAX_TRACKED_PAYLOAD = 4096U;

    explicit LatencyTracker(RingBuffer& aRing) noexcept;

    // Write aPayloadLen bytes with an embedded write timestamp.
    // Returns: OK on success.
    //          INVALID_ARGUMENT   if aPayloadLen == 0 or > MAX_TRACKED_PAYLOAD.
    //          RESOURCE_EXHAUSTED if the ring is too full.
    [[nodiscard]] Result<void> write(const void* aData, U32 aPayloadLen) noexcept;

    // Read the next message, record its write-to-read latency, and copy
    // aPayloadLen bytes into aBuf.
    // Returns: payload bytes written to aBuf on success.
    //          NOT_FOUND          if the ring is empty.
    //          RESOURCE_EXHAUSTED if aBufLen < payload size.
    [[nodiscard]] Result<U32> read(void* aBuf, U32 aBufLen) noexcept;

    [[nodiscard]] const LatencyHistogram& histogram() const noexcept;
    [[nodiscard]] LatencyHistogram&       histogram()       noexcept;

private:
    RingBuffer&      m_ring;
    LatencyHistogram m_histogram;
};

} // namespace ipc
} // namespace astra

#endif // ASTRA_IPC_LATENCY_TRACKER_HPP
