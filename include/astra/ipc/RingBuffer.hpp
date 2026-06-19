// ============================================================================
// Astra Runtime - M-03 Ring Buffer (Sprint 2 + Sprint 3)
// include/astra/ipc/RingBuffer.hpp
//
// Sprint 2: Single-producer / single-consumer ring buffer with framed messages.
//           Wraps the shared ChannelControlBlock that lives inside the memfd
//           region created by ChannelFactory (Sprint 1).
//
// Sprint 3: Wait-free blocking read using C++20 atomic::wait() / notify_one()
//           so the reader thread sleeps on futex instead of busy-waiting.
//
// Wire format per message:
//   [MessageHeader 8 B][payload N B]
//
// Indices:
//   write_index and read_index are monotonically increasing byte offsets.
//   Actual ring position = index % ring_buffer_bytes.
//   Used bytes           = write_index - read_index.
//   Free bytes           = ring_buffer_bytes - used_bytes.
//
// Thread safety:
//   Exactly ONE writer and ONE reader are safe concurrently (SPSC).
//   Multiple writers or multiple readers require external locking (out of scope
//   until a later sprint adds the spinlock promotion path).
// ============================================================================
#ifndef ASTRA_IPC_RING_BUFFER_HPP
#define ASTRA_IPC_RING_BUFFER_HPP

#include <astra/common/result.h>
#include <astra/ipc/Types.hpp>

#include <cstddef>
#include <cstdint>

namespace astra
{
namespace ipc
{

// ---------------------------------------------------------------------------
// MessageHeader - 8-byte prefix placed before every payload in the ring.
//
// m_uPayloadBytes  : number of payload bytes that follow.
// m_uSequenceNo    : monotonically increasing counter maintained by the
//                    writer.  Sprint 8 (Replay Guard) will validate this;
//                    for now it is written and preserved but not checked on
//                    the read path.
// ---------------------------------------------------------------------------
struct alignas(4) MessageHeader
{
    U32 m_uPayloadBytes = 0;
    U32 m_uSequenceNo   = 0;
};

static_assert(sizeof(MessageHeader) == 8U,
              "MessageHeader wire size must be exactly 8 bytes");

// ---------------------------------------------------------------------------
// RingOccupancy - Sprint 9 capacity snapshot
//
// m_uUsedBytes    : bytes currently in flight (all headers + payloads).
//                   Derived from atomic indices — always accurate.
// m_uTotalBytes   : total ring capacity in bytes.
// m_uMessageCount : real messages waiting to be read (SKIP records excluded).
//                   Derived from a header scan — accurate for plain-write
//                   channels; may undercount on HMAC channels (32-byte tags
//                   shift header alignment).
// m_uSkipCount    : SKIP sentinel records left by MPSC overcommit.
// ---------------------------------------------------------------------------
struct RingOccupancy
{
    U32 m_uUsedBytes    = 0U;
    U32 m_uTotalBytes   = 0U;
    U32 m_uMessageCount = 0U;
    U32 m_uSkipCount    = 0U;
};

// ---------------------------------------------------------------------------
// RingBuffer
//
// Constructed from pointers obtained via Channel::control() and
// Channel::ringBuffer().  Does NOT own the memory.
// ---------------------------------------------------------------------------
class RingBuffer
{
public:
    // Construct from the three regions produced by ChannelFactory::createChannel.
    //   aControl    : points to the ChannelControlBlock in shared memory.
    //   aRingStart  : points to the first byte of the ring data region.
    //   aRingBytes  : capacity of the ring data region in bytes.
    RingBuffer(
        ChannelControlBlock* aControl,
        std::byte*           aRingStart,
        U32                  aRingBytes
    ) noexcept;

    // -----------------------------------------------------------------------
    // Sprint 2 - Core write / read
    // -----------------------------------------------------------------------

    // Write one framed message.
    // Returns: OK on success.
    //          RESOURCE_EXHAUSTED if there is not enough free space.
    //          INVALID_ARGUMENT   if aPayloadLen is 0 or overflows U32.
    [[nodiscard]] Result<void> write(const void* aData, U32 aPayloadLen) noexcept;

    // Read the oldest framed message into aBuf.
    // Returns: number of payload bytes written to aBuf on success.
    //          NOT_FOUND          if the ring is empty.
    //          RESOURCE_EXHAUSTED if aBufLen is too small for the next payload.
    [[nodiscard]] Result<U32> read(void* aBuf, U32 aBufLen) noexcept;

    // Inspect the payload size of the next message without consuming it.
    // Returns: payload size on success.
    //          NOT_FOUND if the ring is empty.
    [[nodiscard]] Result<U32> peekNextSize() const noexcept;

    // Number of bytes the ring can accept before it is full.
    // (Includes the 8-byte MessageHeader overhead per message.)
    [[nodiscard]] U32 freeBytes() const noexcept;

    // Number of bytes currently occupied (header + payload for all messages).
    [[nodiscard]] U32 usedBytes() const noexcept;

    // True when no messages are waiting.
    [[nodiscard]] bool isEmpty() const noexcept;

    // True when a message of aPayloadLen bytes cannot fit (including header).
    [[nodiscard]] bool isFull(U32 aPayloadLen) const noexcept;

    // -----------------------------------------------------------------------
    // Sprint 10 - Channel epoch / revocation
    //
    // revokeChannel : atomically increments the epoch in the control block.
    //                 Every reader that calls readChecked() afterwards will
    //                 receive CHANNEL_REVOKED — O(1), no per-reader state.
    //                 Also wakes any threads blocked on a futex so they can
    //                 observe the revocation promptly.
    //
    // isRevoked     : true if the epoch is non-zero (channel revoked).
    //
    // readChecked   : read with epoch pre-check.  Returns CHANNEL_REVOKED
    //                 immediately if the channel has been revoked, even when
    //                 data is present in the ring.
    // -----------------------------------------------------------------------
    void revokeChannel() noexcept;
    [[nodiscard]] bool isRevoked() const noexcept;
    [[nodiscard]] Result<U32> readChecked(void* aBuf, U32 aBufLen) noexcept;

    // -----------------------------------------------------------------------
    // Sprint 9 - Capacity snapshot
    //
    // Returns a consistent point-in-time view of ring occupancy.
    // Byte fields (m_uUsedBytes, m_uTotalBytes) come from atomic indices and
    // are always exact.  m_uMessageCount and m_uSkipCount come from a forward
    // header scan that stops safely if it hits a truncated record.
    // -----------------------------------------------------------------------
    [[nodiscard]] RingOccupancy occupancy() const noexcept;

    // Raw index accessors (useful for tests and the replay guard).
    [[nodiscard]] U64 writeIndex() const noexcept;
    [[nodiscard]] U64 readIndex()  const noexcept;

    // -----------------------------------------------------------------------
    // Sprint 3 - Atomic wait / notify (no busy-wait)
    // -----------------------------------------------------------------------

    // Same as write() but also wakes any thread blocked in readWait().
    // The notify is issued only when write() succeeds.
    [[nodiscard]] Result<void> writeNotify(const void* aData, U32 aPayloadLen) noexcept;

    // Blocking read.  If the ring is empty, the calling thread sleeps via
    // std::atomic::wait() (maps to a futex on Linux) until the writer calls
    // writeNotify().  When data arrives, reads exactly one message.
    //
    // Returns: number of payload bytes written to aBuf on success.
    //          RESOURCE_EXHAUSTED if aBufLen is too small for the next payload
    //                             (the message is left in the ring).
    [[nodiscard]] Result<U32> readWait(void* aBuf, U32 aBufLen) noexcept;

    // -----------------------------------------------------------------------
    // Sprint 4 - HMAC-authenticated write / read
    //
    // Wire format: [MessageHeader 8B][Payload NB][HmacTag 32B]
    //   m_uPayloadBytes in the header = N  (does NOT count the tag).
    //
    // HMAC domain input (multi-part, no allocation):
    //   channel_id(U32) || seq_no(U32) || payload_len(U32) || payload(N B)
    //
    // A null key (all-zero) is rejected — callers must supply a real secret.
    // Use the writeNotifyHmac / readWaitVerify variants for blocking I/O.
    // -----------------------------------------------------------------------

    // Authenticated write.
    // Returns: OK on success.
    //          INVALID_ARGUMENT   if payload is empty or key is null.
    //          RESOURCE_EXHAUSTED if the ring is too full.
    [[nodiscard]] Result<void> writeHmac(
        const HmacKey& aKey,
        const void*    aData,
        U32            aPayloadLen
    ) noexcept;

    // Authenticated read + verify.
    // Returns: payload byte count on success.
    //          NOT_FOUND              if the ring is empty.
    //          RESOURCE_EXHAUSTED     if aBufLen < payload size.
    //          HMAC_VERIFICATION_FAIL if the MAC does not match.
    [[nodiscard]] Result<U32> readVerify(
        const HmacKey& aKey,
        void*          aBuf,
        U32            aBufLen
    ) noexcept;

    // -----------------------------------------------------------------------
    // Sprint 8 - Replay Guard
    //
    // readVerifySeq extends readVerify with a monotone sequence check.
    //
    // aInOutExpectedSeq — the caller's running expected sequence number.
    //   On success the value is incremented so the caller passes it back
    //   unchanged on the next call.  On any failure it is NOT modified, so
    //   the caller continues expecting the same sequence number.
    //
    // Checks performed in order:
    //   1. HMAC tag (constant-time) → HMAC_VERIFICATION_FAIL if bad.
    //   2. Sequence number           → REPLAY_DETECTED if != expected.
    //
    // SKIP sentinel records (seq == 0xFFFF'FFFF, left by the MPSC fast path)
    // are silently consumed without touching aInOutExpectedSeq.
    //
    // The message is always consumed (read index advances) so the channel
    // cannot stall on a rejected record.
    // -----------------------------------------------------------------------

    [[nodiscard]] Result<U32> readVerifySeq(
        const HmacKey& aKey,
        void*          aBuf,
        U32            aBufLen,
        U32&           aInOutExpectedSeq
    ) noexcept;

    // writeHmac + futex notify (for blocking reader).
    [[nodiscard]] Result<void> writeNotifyHmac(
        const HmacKey& aKey,
        const void*    aData,
        U32            aPayloadLen
    ) noexcept;

    // Blocking readVerify.  Sleeps via futex until writeNotifyHmac wakes it.
    [[nodiscard]] Result<U32> readWaitVerify(
        const HmacKey& aKey,
        void*          aBuf,
        U32            aBufLen
    ) noexcept;

    // -----------------------------------------------------------------------
    // Sprint 5 - Capability-gated write / read
    //
    // Each method validates the token against the CapabilityManager before
    // touching the ring.  On PERMISSION_DENIED the ring is untouched —
    // write_claim_index is NOT advanced, leaving zero ring footprint.
    //
    // write*Gated checks Permission::IPC_SEND.
    // read*Gated  checks Permission::IPC_RECV (re-validated after futex wake).
    //
    // A null gate (manager == nullptr or invalid token) always returns
    // PERMISSION_DENIED without consulting the manager.
    // -----------------------------------------------------------------------

    // Capability-gated write.
    // Returns: OK on success.
    //          PERMISSION_DENIED  if token is null, revoked, or lacks IPC_SEND.
    //          INVALID_ARGUMENT   if payload is empty.
    //          RESOURCE_EXHAUSTED if the ring is full.
    [[nodiscard]] Result<void> writeGated(
        const CapabilityGate& aGate,
        const void*           aData,
        U32                   aPayloadLen
    ) noexcept;

    // Capability-gated read.
    // Returns: payload byte count on success.
    //          PERMISSION_DENIED  if token is null, revoked, or lacks IPC_RECV.
    //          NOT_FOUND          if the ring is empty.
    //          RESOURCE_EXHAUSTED if aBufLen < payload size.
    [[nodiscard]] Result<U32> readGated(
        const CapabilityGate& aGate,
        void*                 aBuf,
        U32                   aBufLen
    ) noexcept;

    // writeGated + futex notify.
    [[nodiscard]] Result<void> writeNotifyGated(
        const CapabilityGate& aGate,
        const void*           aData,
        U32                   aPayloadLen
    ) noexcept;

    // Blocking readGated.  Re-validates the token after each futex wake.
    [[nodiscard]] Result<U32> readWaitGated(
        const CapabilityGate& aGate,
        void*                 aBuf,
        U32                   aBufLen
    ) noexcept;

private:
    // Copy aLen bytes from aSrc into the ring starting at byte offset aStartIdx
    // (modulo ring size).  Handles wraparound silently.
    void ringCopyIn(U64 aStartIdx, const void* aSrc, U32 aLen) noexcept;

    // Copy aLen bytes from the ring starting at byte offset aStartIdx
    // (modulo ring size) into aDst.  Handles wraparound silently.
    void ringCopyOut(U64 aStartIdx, void* aDst, U32 aLen) const noexcept;

    // Claim aUTotal bytes in the ring using the CAS (lock-free) path.
    // Fills *aOutClaimStart with the start offset on success.
    [[nodiscard]] Result<U64> claimSlot(U32 aUTotal) noexcept;

    // Publish the claimed slot to readers by advancing the committed
    // write index from aClaimStart to aClaimStart + aUTotal.
    void commitSlot(U64 aClaimStart, U32 aUTotal) noexcept;

    ChannelControlBlock* m_pControl;
    std::byte*           m_pRing;
    U32                  m_uRingBytes;
    U32                  m_uNextSeq = 0U;  // writer-side sequence counter
};

} // namespace ipc
} // namespace astra

#endif // ASTRA_IPC_RING_BUFFER_HPP
