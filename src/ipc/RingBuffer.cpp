// ============================================================================
// Astra Runtime - M-03 Ring Buffer
// src/ipc/RingBuffer.cpp
//
// Sprint 2: Framed write / read with full MPSC write-claim protocol.
//   <= 256 B payload  ->  wait-free path  : single fetch_add claims the slot.
//    > 256 B payload  ->  lock-free path  : CAS retry loop claims the slot.
//   Both paths use a spin-commit to serialise the committed write index so the
//   reader always sees a contiguous, ordered stream regardless of how many
//   producers are racing.
//
// If a fetch_add overcommits (ring was fuller than the pre-check suggested),
// a SKIP sentinel record is written so the reader can advance past the wasted
// region without stalling.
//
// Sprint 3: Blocking read via std::atomic::wait() / notify_one() (futex).
// ============================================================================

#include <astra/ipc/RingBuffer.hpp>
#include <astra/common/log.h>

#include <algorithm>
#include <atomic>
#include <cstring>
#include <limits>
#include <thread>

namespace astra
{
namespace ipc
{

namespace
{
constexpr const char* LOG_TAG       = "ipc_ring";
constexpr U32         SMALL_MSG_MAX = 256U;  // threshold: fetch_add vs CAS

// Sequence number written into every SKIP sentinel so the reader can
// identify and discard wasted slots left by overcommitting producers.
constexpr U32 SKIP_SENTINEL_SEQ = 0xFFFF'FFFFU;
} // namespace

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

RingBuffer::RingBuffer(
    ChannelControlBlock* aControl,
    std::byte*           aRingStart,
    U32                  aRingBytes
) noexcept
    : m_pControl(aControl)
    , m_pRing(aRingStart)
    , m_uRingBytes(aRingBytes)
    , m_uNextSeq(0U)
{
}

// ---------------------------------------------------------------------------
// Private helpers — ring-wrapping byte copy
// ---------------------------------------------------------------------------

void RingBuffer::ringCopyIn(U64 aStartIdx, const void* aSrc, U32 aLen) noexcept
{
    const U32 lUPos        = static_cast<U32>(aStartIdx % static_cast<U64>(m_uRingBytes));
    const U32 lUFirstChunk = std::min(aLen, m_uRingBytes - lUPos);

    std::memcpy(m_pRing + lUPos, aSrc, lUFirstChunk);

    if (lUFirstChunk < aLen)
    {
        std::memcpy(
            m_pRing,
            static_cast<const std::byte*>(aSrc) + lUFirstChunk,
            aLen - lUFirstChunk
        );
    }
}

void RingBuffer::ringCopyOut(U64 aStartIdx, void* aDst, U32 aLen) const noexcept
{
    const U32 lUPos        = static_cast<U32>(aStartIdx % static_cast<U64>(m_uRingBytes));
    const U32 lUFirstChunk = std::min(aLen, m_uRingBytes - lUPos);

    std::memcpy(aDst, m_pRing + lUPos, lUFirstChunk);

    if (lUFirstChunk < aLen)
    {
        std::memcpy(
            static_cast<std::byte*>(aDst) + lUFirstChunk,
            m_pRing,
            aLen - lUFirstChunk
        );
    }
}

// ---------------------------------------------------------------------------
// State accessors
// ---------------------------------------------------------------------------

U64 RingBuffer::writeIndex() const noexcept
{
    return m_pControl->m_write.m_uWriteIndex.load(std::memory_order_acquire);
}

U64 RingBuffer::readIndex() const noexcept
{
    return m_pControl->m_read.m_uReadIndex.load(std::memory_order_acquire);
}

U32 RingBuffer::usedBytes() const noexcept
{
    const U64 lUUsed = writeIndex() - readIndex();
    return (lUUsed > static_cast<U64>(m_uRingBytes))
               ? m_uRingBytes
               : static_cast<U32>(lUUsed);
}

U32 RingBuffer::freeBytes() const noexcept
{
    return m_uRingBytes - usedBytes();
}

bool RingBuffer::isEmpty() const noexcept
{
    return writeIndex() == readIndex();
}

bool RingBuffer::isFull(U32 aPayloadLen) const noexcept
{
    return static_cast<U32>(sizeof(MessageHeader)) + aPayloadLen > freeBytes();
}

// ---------------------------------------------------------------------------
// Sprint 2 - write (MPSC-capable)
//
// TWO-PHASE PROTOCOL
// ==================
// Phase 1 – CLAIM
//   The producer atomically reserves a contiguous byte range in the ring by
//   advancing write_claim_index.
//
//   <= SMALL_MSG_MAX bytes payload  (wait-free):
//     Pre-check free space, then unconditionally fetch_add to claim.
//     If the post-claim space check fails (two producers both saw free space
//     but only one fits), write a SKIP sentinel at the claimed position,
//     commit it, and return RESOURCE_EXHAUSTED.  The reader silently skips
//     SKIP records and advances past them.
//
//   >  SMALL_MSG_MAX bytes payload  (lock-free):
//     CAS loop: re-read claim index and free space each iteration until the
//     CAS succeeds.  Only claims when there is definitely room.
//
// Phase 2 – COMMIT
//   After writing the data into the ring, the producer must serialise with
//   any earlier producers that claimed a lower offset.  It spins on
//   write_index (the committed cursor) until it equals our claim_start,
//   then advances write_index to claim_start + total.  This guarantees
//   the reader always sees a gap-free, ordered byte stream.
// ---------------------------------------------------------------------------

Result<void> RingBuffer::write(const void* aData, U32 aPayloadLen) noexcept
{
    // ---- basic validation --------------------------------------------------
    if (aPayloadLen == 0U)
    {
        return std::unexpected(makeError(
            ErrorCode::INVALID_ARGUMENT,
            ErrorCategory::IPC,
            "write: payload length must be greater than zero"
        ));
    }

    if (aPayloadLen > std::numeric_limits<U32>::max() - static_cast<U32>(sizeof(MessageHeader)))
    {
        return std::unexpected(makeError(
            ErrorCode::INVALID_ARGUMENT,
            ErrorCategory::IPC,
            "write: payload causes header+payload to overflow U32"
        ));
    }

    const U32 lUTotal = static_cast<U32>(sizeof(MessageHeader)) + aPayloadLen;

    // ---- Phase 1: CLAIM ---------------------------------------------------

    U64 lUClaimStart = 0U;

    if (aPayloadLen <= SMALL_MSG_MAX)
    {
        // -- wait-free path: single fetch_add --
        //
        // Pre-check: snapshot read_idx and current claim so we have a
        // reasonable estimate of free space before committing.
        const U64 lUReadIdx      = m_pControl->m_read.m_uReadIndex
                                       .load(std::memory_order_acquire);
        const U64 lUCurrentClaim = m_pControl->m_write.m_uWriteClaimIndex
                                       .load(std::memory_order_relaxed);

        if (lUCurrentClaim - lUReadIdx + static_cast<U64>(lUTotal)
                > static_cast<U64>(m_uRingBytes))
        {
            return std::unexpected(makeError(
                ErrorCode::RESOURCE_EXHAUSTED,
                ErrorCategory::IPC,
                "write: ring full (pre-check, small message path)"
            ));
        }

        // Unconditionally claim — wait-free (one atomic instruction)
        lUClaimStart = m_pControl->m_write.m_uWriteClaimIndex
                           .fetch_add(static_cast<U64>(lUTotal),
                                      std::memory_order_acq_rel);

        // Post-claim verification: another producer may have slipped in
        // between our pre-check and the fetch_add.
        const U64 lUReadIdxNow = m_pControl->m_read.m_uReadIndex
                                     .load(std::memory_order_acquire);

        if (lUClaimStart - lUReadIdxNow + static_cast<U64>(lUTotal)
                > static_cast<U64>(m_uRingBytes))
        {
            // Overcommitted: write a SKIP sentinel so the reader can
            // advance past our claimed-but-invalid slot, then bail out.
            MessageHeader lSkip{};
            lSkip.m_uPayloadBytes = aPayloadLen;   // tells reader how far to skip
            lSkip.m_uSequenceNo   = SKIP_SENTINEL_SEQ;
            ringCopyIn(lUClaimStart, &lSkip, static_cast<U32>(sizeof(MessageHeader)));

            // Commit the SKIP record (ordered with any prior producers)
            U64 lUExpected = lUClaimStart;
            while (!m_pControl->m_write.m_uWriteIndex
                        .compare_exchange_weak(lUExpected,
                                               lUClaimStart + static_cast<U64>(lUTotal),
                                               std::memory_order_release,
                                               std::memory_order_relaxed))
            {
                lUExpected = lUClaimStart;
                std::atomic_thread_fence(std::memory_order_acquire);
            }

            ASTRA_LOG_WARN(LOG_TAG,
                "write: overcommit on small-msg path — SKIP sentinel at idx %llu (channel %u)",
                static_cast<unsigned long long>(lUClaimStart),
                m_pControl->m_meta.m_uChannelId);

            return std::unexpected(makeError(
                ErrorCode::RESOURCE_EXHAUSTED,
                ErrorCategory::IPC,
                "write: ring full (post-claim overcommit, small message path)"
            ));
        }
    }
    else
    {
        // -- lock-free path: CAS retry loop --
        U64 lUExpectedClaim = m_pControl->m_write.m_uWriteClaimIndex
                                  .load(std::memory_order_relaxed);

        while (true)
        {
            const U64 lUReadIdx = m_pControl->m_read.m_uReadIndex
                                      .load(std::memory_order_acquire);

            if (lUExpectedClaim - lUReadIdx + static_cast<U64>(lUTotal)
                    > static_cast<U64>(m_uRingBytes))
            {
                return std::unexpected(makeError(
                    ErrorCode::RESOURCE_EXHAUSTED,
                    ErrorCategory::IPC,
                    "write: ring full (CAS path, large message)"
                ));
            }

            if (m_pControl->m_write.m_uWriteClaimIndex
                    .compare_exchange_weak(lUExpectedClaim,
                                           lUExpectedClaim + static_cast<U64>(lUTotal),
                                           std::memory_order_acq_rel,
                                           std::memory_order_relaxed))
            {
                lUClaimStart = lUExpectedClaim;
                break;
            }
            // CAS failed — lUExpectedClaim refreshed by compare_exchange_weak; retry
        }
    }

    // ---- Write header + payload into the claimed region -------------------

    MessageHeader lHeader{};
    lHeader.m_uPayloadBytes = aPayloadLen;
    lHeader.m_uSequenceNo   = m_uNextSeq++;

    ringCopyIn(lUClaimStart,
               &lHeader,
               static_cast<U32>(sizeof(MessageHeader)));

    ringCopyIn(lUClaimStart + static_cast<U64>(sizeof(MessageHeader)),
               aData,
               aPayloadLen);

    // ---- Phase 2: COMMIT --------------------------------------------------
    // Spin until write_index == lUClaimStart (all prior producers committed),
    // then advance write_index to publish our message to the reader.

    U64 lUExpectedCommit = lUClaimStart;
    while (!m_pControl->m_write.m_uWriteIndex
                .compare_exchange_weak(lUExpectedCommit,
                                       lUClaimStart + static_cast<U64>(lUTotal),
                                       std::memory_order_release,
                                       std::memory_order_relaxed))
    {
        lUExpectedCommit = lUClaimStart;
        std::atomic_thread_fence(std::memory_order_acquire);
    }

    ASTRA_LOG_TRACE(LOG_TAG,
        "write: seq=%u payload=%u bytes path=%s (channel %u)",
        lHeader.m_uSequenceNo,
        aPayloadLen,
        (aPayloadLen <= SMALL_MSG_MAX) ? "fetch_add" : "CAS",
        m_pControl->m_meta.m_uChannelId);

    return {};
}

// ---------------------------------------------------------------------------
// Sprint 2 - read
//
// Reads one framed message, transparently skipping SKIP sentinel records
// left by overcommitting producers on the small-message path.
// ---------------------------------------------------------------------------

Result<U32> RingBuffer::read(void* aBuf, U32 aBufLen) noexcept
{
    while (true)
    {
        const U64 lUWriteIdx = m_pControl->m_write.m_uWriteIndex
                                   .load(std::memory_order_acquire);
        const U64 lUReadIdx  = m_pControl->m_read.m_uReadIndex
                                   .load(std::memory_order_relaxed);
        const U64 lUAvail    = lUWriteIdx - lUReadIdx;

        if (lUAvail < static_cast<U64>(sizeof(MessageHeader)))
        {
            return std::unexpected(makeError(
                ErrorCode::NOT_FOUND,
                ErrorCategory::IPC,
                "read: ring buffer is empty"
            ));
        }

        MessageHeader lHeader{};
        ringCopyOut(lUReadIdx, &lHeader, static_cast<U32>(sizeof(MessageHeader)));

        const U64 lUMsgTotal = static_cast<U64>(sizeof(MessageHeader))
                             + static_cast<U64>(lHeader.m_uPayloadBytes);

        if (lUAvail < lUMsgTotal)
        {
            return std::unexpected(makeError(
                ErrorCode::PRECONDITION_FAILED,
                ErrorCategory::IPC,
                "read: partial message in ring (write index inconsistency)"
            ));
        }

        // Silently consume SKIP sentinel records
        if (lHeader.m_uSequenceNo == SKIP_SENTINEL_SEQ)
        {
            m_pControl->m_read.m_uReadIndex
                .store(lUReadIdx + lUMsgTotal, std::memory_order_release);
            ASTRA_LOG_TRACE(LOG_TAG,
                "read: consumed SKIP sentinel (%u bytes) (channel %u)",
                lHeader.m_uPayloadBytes,
                m_pControl->m_meta.m_uChannelId);
            continue;  // re-check for the next real message
        }

        if (aBufLen < lHeader.m_uPayloadBytes)
        {
            return std::unexpected(makeError(
                ErrorCode::RESOURCE_EXHAUSTED,
                ErrorCategory::IPC,
                "read: destination buffer too small for next message payload"
            ));
        }

        ringCopyOut(lUReadIdx + static_cast<U64>(sizeof(MessageHeader)),
                    aBuf,
                    lHeader.m_uPayloadBytes);

        m_pControl->m_read.m_uReadIndex
            .store(lUReadIdx + lUMsgTotal, std::memory_order_release);

        ASTRA_LOG_TRACE(LOG_TAG,
            "read: seq=%u payload=%u bytes (channel %u)",
            lHeader.m_uSequenceNo,
            lHeader.m_uPayloadBytes,
            m_pControl->m_meta.m_uChannelId);

        return lHeader.m_uPayloadBytes;
    }
}

// ---------------------------------------------------------------------------
// Sprint 2 - peekNextSize (skips SKIP records, does not consume)
// ---------------------------------------------------------------------------

Result<U32> RingBuffer::peekNextSize() const noexcept
{
    U64 lUScanIdx = m_pControl->m_read.m_uReadIndex
                        .load(std::memory_order_relaxed);
    const U64 lUWriteIdx = m_pControl->m_write.m_uWriteIndex
                               .load(std::memory_order_acquire);

    while (true)
    {
        if (lUWriteIdx - lUScanIdx < static_cast<U64>(sizeof(MessageHeader)))
        {
            return std::unexpected(makeError(
                ErrorCode::NOT_FOUND,
                ErrorCategory::IPC,
                "peekNextSize: ring buffer is empty"
            ));
        }

        MessageHeader lHeader{};
        ringCopyOut(lUScanIdx, &lHeader, static_cast<U32>(sizeof(MessageHeader)));

        if (lHeader.m_uSequenceNo == SKIP_SENTINEL_SEQ)
        {
            // Skip over this sentinel and look at the next record
            lUScanIdx += static_cast<U64>(sizeof(MessageHeader))
                       + static_cast<U64>(lHeader.m_uPayloadBytes);
            continue;
        }

        return lHeader.m_uPayloadBytes;
    }
}

// ---------------------------------------------------------------------------
// Sprint 3 - writeNotify
// ---------------------------------------------------------------------------

Result<void> RingBuffer::writeNotify(const void* aData, U32 aPayloadLen) noexcept
{
    auto lResult = write(aData, aPayloadLen);
    if (lResult.has_value())
    {
        m_pControl->m_write.m_uWriteIndex.notify_one();
    }
    return lResult;
}

// ---------------------------------------------------------------------------
// Sprint 3 - readWait (blocking read, no busy-wait)
// ---------------------------------------------------------------------------

Result<U32> RingBuffer::readWait(void* aBuf, U32 aBufLen) noexcept
{
    while (true)
    {
        const U64 lUCurWrite = m_pControl->m_write.m_uWriteIndex
                                   .load(std::memory_order_acquire);
        const U64 lUCurRead  = m_pControl->m_read.m_uReadIndex
                                   .load(std::memory_order_relaxed);

        if (lUCurWrite - lUCurRead >= static_cast<U64>(sizeof(MessageHeader)))
        {
            return read(aBuf, aBufLen);
        }

        m_pControl->m_write.m_uWriteIndex.wait(lUCurWrite, std::memory_order_acquire);
    }
}

} // namespace ipc
} // namespace astra
