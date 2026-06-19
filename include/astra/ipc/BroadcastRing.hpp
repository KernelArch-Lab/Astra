// ============================================================================
// Astra Runtime - M-03 IPC Sprint 11 / 12: Multicast Fan-Out + Zero-Copy Loan
// include/astra/ipc/BroadcastRing.hpp
//
// BroadcastRing wraps a single shared-memory ring and N independent per-reader
// cursors so that one writer can deliver the same stream to multiple readers.
//
// Wire format per message: [MessageHeader 8 B][payload N B]  (plain, no tag)
//
// Writer semantics:
//   broadcast() copies the caller's buffer into the ring (one memcpy).
//   loan() / commit() is the zero-copy path: the writer fills the ring slot
//   directly in-place with no intermediate buffer.
//   Free space is limited by the SLOWEST reader (min cursor).
//
// Reader semantics:
//   read(slot, ...) advances only the cursor for that slot, leaving all other
//   cursors untouched.  Readers are completely independent.
//
// Limits:
//   MAX_READERS = 8.  The caller provides the ReaderCursor array (stack,
//   static, or a mapped second memfd — BroadcastRing is policy-free).
//
// Thread safety:
//   Exactly ONE writer thread calling broadcast() / loan() / commit().
//   Each reader slot may be driven by its own thread.
// ============================================================================
#ifndef ASTRA_IPC_BROADCAST_RING_HPP
#define ASTRA_IPC_BROADCAST_RING_HPP

#include <astra/common/result.h>
#include <astra/ipc/Types.hpp>

#include <cstddef>
#include <cstdint>

namespace astra
{
namespace ipc
{

// ---------------------------------------------------------------------------
// BufferLoan - Sprint 12: zero-copy write descriptor.
//
// Returned by BroadcastRing::loan().  The caller writes payload bytes
// directly into m_pPayload[0 .. m_uPayloadLen-1], then calls
// BroadcastRing::commit() to publish the message.
//
// Invariant: m_pPayload points into a contiguous, ring-boundary-aligned
// region — it never crosses the ring wrap point.  loan() returns
// RESOURCE_EXHAUSTED instead of issuing a loan that would wrap.
//
// A loan MUST be committed before the next loan() or broadcast() call.
// Abandoning a loan (no commit) leaves the ring write_index unchanged;
// the slot is silently reclaimed by the next loan/broadcast.
// ---------------------------------------------------------------------------
struct BufferLoan
{
    std::byte* m_pPayload    = nullptr;
    U32        m_uPayloadLen = 0U;
    U64        m_uWriteIdx   = 0U;   // ring index at the start of this loan
    bool       m_bValid      = false;
};

class BroadcastRing
{
public:
    static constexpr U32 MAX_READERS = 8U;

    // Construct from pre-mapped regions.
    //   aControl    : ChannelControlBlock from the ring channel.
    //   aRingStart  : first byte of the ring data region.
    //   aRingBytes  : ring capacity in bytes.
    //   aCursors    : array of aNumReaders ReaderCursor objects (caller-owned).
    //   aNumReaders : 1 .. MAX_READERS.
    BroadcastRing(
        ChannelControlBlock* aControl,
        std::byte*           aRingStart,
        U32                  aRingBytes,
        ReaderCursor*        aCursors,
        U32                  aNumReaders
    ) noexcept;

    // -----------------------------------------------------------------------
    // Writer API
    // -----------------------------------------------------------------------

    // Broadcast one message to all readers.
    // Free space is limited by the slowest reader (minimum cursor).
    // Returns: OK on success.
    //          INVALID_ARGUMENT   if aPayloadLen is 0.
    //          RESOURCE_EXHAUSTED if the slowest reader has not caught up.
    [[nodiscard]] Result<void> broadcast(const void* aData, U32 aPayloadLen) noexcept;

    // Bytes available for the writer (ring capacity minus lagging-reader backlog).
    [[nodiscard]] U32 freeBytesForWriter() const noexcept;

    // -----------------------------------------------------------------------
    // Sprint 12 - Zero-copy buffer loan
    //
    // loan()   : claim a contiguous slot in the ring and return a BufferLoan
    //            whose m_pPayload the caller fills directly (no memcpy).
    //            Returns INVALID_ARGUMENT   if aPayloadLen is 0.
    //            Returns RESOURCE_EXHAUSTED if the slot would cross the ring
    //            wrap boundary (use broadcast() as fallback for that case) or
    //            if the slowest reader has not freed enough space.
    //
    // commit() : write the MessageHeader and publish the slot to readers by
    //            advancing write_index.  Must be called with the BufferLoan
    //            returned by the most recent loan() call.  The sequence number
    //            is assigned here (not at loan time) so abandoned loans leave
    //            no seq gap.
    // -----------------------------------------------------------------------
    [[nodiscard]] Result<BufferLoan> loan(U32 aPayloadLen) noexcept;
    void commit(const BufferLoan& aLoan) noexcept;

    // -----------------------------------------------------------------------
    // Reader API
    // -----------------------------------------------------------------------

    // Read the next message for reader slot aSlot.
    // Only the cursor for aSlot is advanced; other slots are unaffected.
    // Returns: payload bytes written to aBuf on success.
    //          INVALID_ARGUMENT   if aSlot >= numReaders().
    //          NOT_FOUND          if the reader is caught up with the writer.
    //          RESOURCE_EXHAUSTED if aBufLen < next payload size.
    [[nodiscard]] Result<U32> read(U32 aSlot, void* aBuf, U32 aBufLen) noexcept;

    // Bytes available for a specific reader slot.
    [[nodiscard]] U32 availableForReader(U32 aSlot) const noexcept;

    [[nodiscard]] U32 numReaders() const noexcept;

private:
    void ringCopyIn (U64 aStartIdx, const void* aSrc, U32 aLen) noexcept;
    void ringCopyOut(U64 aStartIdx, void*       aDst, U32 aLen) const noexcept;

    [[nodiscard]] U64 minCursor() const noexcept;

    ChannelControlBlock* m_pControl;
    std::byte*           m_pRing;
    U32                  m_uRingBytes;
    ReaderCursor*        m_pCursors;
    U32                  m_uNumReaders;
    U32                  m_uNextSeq = 0U;
};

} // namespace ipc
} // namespace astra

#endif // ASTRA_IPC_BROADCAST_RING_HPP
