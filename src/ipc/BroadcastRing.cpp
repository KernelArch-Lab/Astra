// ============================================================================
// Astra Runtime - M-03 IPC Sprint 11: Multicast Fan-Out
// src/ipc/BroadcastRing.cpp
// ============================================================================

#include <astra/ipc/BroadcastRing.hpp>
#include <astra/ipc/RingBuffer.hpp>
#include <astra/common/log.h>

#include <algorithm>
#include <cstring>
#include <limits>

namespace astra
{
namespace ipc
{

namespace
{
constexpr const char* LOG_TAG = "ipc_broadcast";
} // namespace

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

BroadcastRing::BroadcastRing(
    ChannelControlBlock* aControl,
    std::byte*           aRingStart,
    U32                  aRingBytes,
    ReaderCursor*        aCursors,
    U32                  aNumReaders
) noexcept
    : m_pControl(aControl)
    , m_pRing(aRingStart)
    , m_uRingBytes(aRingBytes)
    , m_pCursors(aCursors)
    , m_uNumReaders(aNumReaders)
    , m_uNextSeq(0U)
{
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

void BroadcastRing::ringCopyIn(U64 aStartIdx, const void* aSrc, U32 aLen) noexcept
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

void BroadcastRing::ringCopyOut(U64 aStartIdx, void* aDst, U32 aLen) const noexcept
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

U64 BroadcastRing::minCursor() const noexcept
{
    U64 lUMin = std::numeric_limits<U64>::max();
    for (U32 i = 0U; i < m_uNumReaders; ++i)
    {
        const U64 lUCursor = m_pCursors[i].m_uReadIndex.load(std::memory_order_acquire);
        if (lUCursor < lUMin)
            lUMin = lUCursor;
    }
    return lUMin;
}

// ---------------------------------------------------------------------------
// freeBytesForWriter / availableForReader
// ---------------------------------------------------------------------------

U32 BroadcastRing::freeBytesForWriter() const noexcept
{
    const U64 lUWriteIdx = m_pControl->m_write.m_uWriteIndex
                               .load(std::memory_order_acquire);
    const U64 lUUsed = lUWriteIdx - minCursor();
    return (lUUsed >= static_cast<U64>(m_uRingBytes))
               ? 0U
               : static_cast<U32>(m_uRingBytes - lUUsed);
}

U32 BroadcastRing::availableForReader(U32 aSlot) const noexcept
{
    if (aSlot >= m_uNumReaders)
        return 0U;

    const U64 lUWriteIdx = m_pControl->m_write.m_uWriteIndex
                               .load(std::memory_order_acquire);
    const U64 lUCursor   = m_pCursors[aSlot].m_uReadIndex
                               .load(std::memory_order_relaxed);
    const U64 lUAvail    = lUWriteIdx - lUCursor;
    return (lUAvail > static_cast<U64>(m_uRingBytes))
               ? m_uRingBytes
               : static_cast<U32>(lUAvail);
}

U32 BroadcastRing::numReaders() const noexcept
{
    return m_uNumReaders;
}

// ---------------------------------------------------------------------------
// Sprint 12 - loan / commit
// ---------------------------------------------------------------------------

Result<BufferLoan> BroadcastRing::loan(U32 aPayloadLen) noexcept
{
    if (aPayloadLen == 0U)
    {
        return std::unexpected(makeError(
            ErrorCode::INVALID_ARGUMENT,
            ErrorCategory::IPC,
            "loan: payload length must be greater than zero"
        ));
    }

    const U32 lUTotal    = static_cast<U32>(sizeof(MessageHeader)) + aPayloadLen;
    const U64 lUWriteIdx = m_pControl->m_write.m_uWriteIndex
                               .load(std::memory_order_relaxed);
    const U32 lUPos      = static_cast<U32>(lUWriteIdx % static_cast<U64>(m_uRingBytes));

    // Reject loans that would cross the ring wrap boundary — the returned
    // pointer must be contiguous.  Use broadcast() for wrapping writes.
    if (lUPos + lUTotal > m_uRingBytes)
    {
        return std::unexpected(makeError(
            ErrorCode::RESOURCE_EXHAUSTED,
            ErrorCategory::IPC,
            "loan: slot would cross ring wrap boundary — use broadcast() instead"
        ));
    }

    if (lUWriteIdx - minCursor() + static_cast<U64>(lUTotal)
            > static_cast<U64>(m_uRingBytes))
    {
        return std::unexpected(makeError(
            ErrorCode::RESOURCE_EXHAUSTED,
            ErrorCategory::IPC,
            "loan: ring full — slowest reader has not caught up"
        ));
    }

    BufferLoan lLoan{};
    lLoan.m_pPayload    = m_pRing + lUPos + static_cast<U32>(sizeof(MessageHeader));
    lLoan.m_uPayloadLen = aPayloadLen;
    lLoan.m_uWriteIdx   = lUWriteIdx;
    lLoan.m_bValid      = true;

    return lLoan;
}

void BroadcastRing::commit(const BufferLoan& aLoan) noexcept
{
    // Write the message header into the ring at the loan's start position.
    // loan() guaranteed pos + total ≤ ringBytes so no wrap occurs here.
    MessageHeader lHdr{};
    lHdr.m_uPayloadBytes = aLoan.m_uPayloadLen;
    lHdr.m_uSequenceNo   = m_uNextSeq++;

    const U32 lUPos = static_cast<U32>(aLoan.m_uWriteIdx % static_cast<U64>(m_uRingBytes));
    std::memcpy(m_pRing + lUPos, &lHdr, sizeof(MessageHeader));

    const U64 lUNewWrite = aLoan.m_uWriteIdx
                         + static_cast<U64>(sizeof(MessageHeader))
                         + static_cast<U64>(aLoan.m_uPayloadLen);

    m_pControl->m_write.m_uWriteIndex
        .store(lUNewWrite, std::memory_order_release);
    m_pControl->m_write.m_uWriteClaimIndex
        .store(lUNewWrite, std::memory_order_relaxed);
    m_pControl->m_write.m_uWriteIndex.notify_all();

    ASTRA_LOG_TRACE(LOG_TAG,
        "commit: seq=%u payload=%u bytes zero-copy (channel %u)",
        lHdr.m_uSequenceNo, aLoan.m_uPayloadLen,
        m_pControl->m_meta.m_uChannelId);
}

// ---------------------------------------------------------------------------
// broadcast
//
// Single-writer SPSC write path.  No claim/commit dance needed since there
// is exactly one producer; write_index is advanced with a single store after
// the data is fully written.
// ---------------------------------------------------------------------------

Result<void> BroadcastRing::broadcast(const void* aData, U32 aPayloadLen) noexcept
{
    if (aPayloadLen == 0U)
    {
        return std::unexpected(makeError(
            ErrorCode::INVALID_ARGUMENT,
            ErrorCategory::IPC,
            "broadcast: payload length must be greater than zero"
        ));
    }

    const U32 lUTotal    = static_cast<U32>(sizeof(MessageHeader)) + aPayloadLen;
    const U64 lUWriteIdx = m_pControl->m_write.m_uWriteIndex
                               .load(std::memory_order_relaxed);
    const U64 lUMinCur   = minCursor();

    if (lUWriteIdx - lUMinCur + static_cast<U64>(lUTotal) > static_cast<U64>(m_uRingBytes))
    {
        return std::unexpected(makeError(
            ErrorCode::RESOURCE_EXHAUSTED,
            ErrorCategory::IPC,
            "broadcast: ring full — slowest reader has not caught up"
        ));
    }

    MessageHeader lHdr{};
    lHdr.m_uPayloadBytes = aPayloadLen;
    lHdr.m_uSequenceNo   = m_uNextSeq++;

    ringCopyIn(lUWriteIdx, &lHdr, static_cast<U32>(sizeof(MessageHeader)));
    ringCopyIn(lUWriteIdx + static_cast<U64>(sizeof(MessageHeader)), aData, aPayloadLen);

    // Publish to all readers with a release store, then wake futex waiters
    const U64 lUNewWrite = lUWriteIdx + static_cast<U64>(lUTotal);
    m_pControl->m_write.m_uWriteIndex.store(lUNewWrite, std::memory_order_release);
    m_pControl->m_write.m_uWriteIndex.notify_all();

    // Keep claim index in sync (matches single-writer invariant)
    m_pControl->m_write.m_uWriteClaimIndex.store(lUNewWrite, std::memory_order_relaxed);

    ASTRA_LOG_TRACE(LOG_TAG,
        "broadcast: seq=%u payload=%u bytes to %u readers (channel %u)",
        lHdr.m_uSequenceNo, aPayloadLen,
        m_uNumReaders, m_pControl->m_meta.m_uChannelId);

    return {};
}

// ---------------------------------------------------------------------------
// read
// ---------------------------------------------------------------------------

Result<U32> BroadcastRing::read(U32 aSlot, void* aBuf, U32 aBufLen) noexcept
{
    if (aSlot >= m_uNumReaders)
    {
        return std::unexpected(makeError(
            ErrorCode::INVALID_ARGUMENT,
            ErrorCategory::IPC,
            "BroadcastRing::read: slot index out of range"
        ));
    }

    const U64 lUWriteIdx = m_pControl->m_write.m_uWriteIndex
                               .load(std::memory_order_acquire);
    const U64 lUCursor   = m_pCursors[aSlot].m_uReadIndex
                               .load(std::memory_order_relaxed);
    const U64 lUAvail    = lUWriteIdx - lUCursor;

    if (lUAvail < static_cast<U64>(sizeof(MessageHeader)))
    {
        return std::unexpected(makeError(
            ErrorCode::NOT_FOUND,
            ErrorCategory::IPC,
            "BroadcastRing::read: no message available for this slot"
        ));
    }

    MessageHeader lHdr{};
    ringCopyOut(lUCursor, &lHdr, static_cast<U32>(sizeof(MessageHeader)));

    const U64 lUMsgTotal = static_cast<U64>(sizeof(MessageHeader))
                         + static_cast<U64>(lHdr.m_uPayloadBytes);

    if (lUAvail < lUMsgTotal)
    {
        return std::unexpected(makeError(
            ErrorCode::PRECONDITION_FAILED,
            ErrorCategory::IPC,
            "BroadcastRing::read: partial message in ring"
        ));
    }

    if (aBufLen < lHdr.m_uPayloadBytes)
    {
        return std::unexpected(makeError(
            ErrorCode::RESOURCE_EXHAUSTED,
            ErrorCategory::IPC,
            "BroadcastRing::read: destination buffer too small"
        ));
    }

    ringCopyOut(lUCursor + static_cast<U64>(sizeof(MessageHeader)),
                aBuf, lHdr.m_uPayloadBytes);

    m_pCursors[aSlot].m_uReadIndex
        .store(lUCursor + lUMsgTotal, std::memory_order_release);

    ASTRA_LOG_TRACE(LOG_TAG,
        "broadcast read: slot=%u seq=%u payload=%u bytes (channel %u)",
        aSlot, lHdr.m_uSequenceNo,
        lHdr.m_uPayloadBytes, m_pControl->m_meta.m_uChannelId);

    return lHdr.m_uPayloadBytes;
}

} // namespace ipc
} // namespace astra
