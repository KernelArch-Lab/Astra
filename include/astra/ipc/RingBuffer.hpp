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
#include <astra/core/capability.h>
#include <astra/ipc/Types.hpp>

#include <cstddef>
#include <cstdint>

namespace astra
{
namespace ipc
{

// ---------------------------------------------------------------------------
// CapabilityGate - the M-01 token bound to one end of an IPC channel.
//
// Track B Sprint 5 of the Paper 1 (USENIX ATC 2027) prep work. The gate is
// what makes the IPC fastpath capability-validated: every gated write/read
// runs CapabilityManager::validate(token, IPC_SEND/RECV) before touching
// the ring. The Sprint 4 slot-indexed validate is what makes that cheap
// enough to put on the hot path (≤80 ns p99 vs the prior linear scan).
//
// A single Channel typically has *two* gates — one stamped IPC_SEND held by
// the producer endpoint, one stamped IPC_RECV held by the consumer endpoint.
// The CapabilityManager pointer is shared; tokens differ.
//
// Lifetimes:
//   - The CapabilityManager outlives every CapabilityGate that points at it.
//   - The gate is cheap (one pointer + one 128-bit token + 8 bytes of perm
//     bits); pass by value or const-ref.
//
// Why a struct and not a constructor parameter on RingBuffer:
//   - The Sprint 1–3 RingBuffer tests construct RingBuffer directly from
//     raw memfd pointers; they do not have a CapabilityManager. Forcing
//     one in would break those tests for no value-add.
//   - The capability-aware path is a *separate* call (writeGated/readGated)
//     so the existing raw API stays available for replay reconstruction
//     (M-05) and for the gate-off arm of the Paper 1 measurement.
// ---------------------------------------------------------------------------
struct CapabilityGate
{
    const astra::core::CapabilityManager* m_pManager   = nullptr;
    astra::core::CapabilityToken          m_token      = astra::core::CapabilityToken::null();

    // Construct an inert gate (no validation will pass through it).
    static CapabilityGate none() noexcept { return CapabilityGate{}; }

    // True iff this gate is bound to a manager + a non-null token.
    [[nodiscard]] bool isBound() const noexcept
    {
        return m_pManager != nullptr && m_token.isValid();
    }
};

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

    // Raw index accessors (useful for tests and the replay guard).
    [[nodiscard]] U64 writeIndex() const noexcept;
    [[nodiscard]] U64 readIndex()  const noexcept;

    // -----------------------------------------------------------------------
    // Sprint 3 - Atomic wait / notify (no busy-wait)
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Sprint 5 - Capability-gated write / read (Paper 1 hot path)
    //
    // These overloads call CapabilityManager::validate(gate.m_token,
    // IPC_SEND/RECV) before touching the ring. They share the *same*
    // claim/commit machinery as write()/read() — the gate is a O(1)
    // pre-flight, not a wrapper layer.
    //
    // Returns:
    //   PERMISSION_DENIED if the gate is unbound, the token is revoked,
    //                     or the token does not carry IPC_SEND/RECV.
    //   anything write()/read() can return otherwise.
    // -----------------------------------------------------------------------
    [[nodiscard]] Result<void> writeGated(
        const CapabilityGate& aGate,
        const void*           aData,
        U32                   aPayloadLen) noexcept;

    [[nodiscard]] Result<U32> readGated(
        const CapabilityGate& aGate,
        void*                 aBuf,
        U32                   aBufLen) noexcept;

    [[nodiscard]] Result<void> writeNotifyGated(
        const CapabilityGate& aGate,
        const void*           aData,
        U32                   aPayloadLen) noexcept;

    [[nodiscard]] Result<U32> readWaitGated(
        const CapabilityGate& aGate,
        void*                 aBuf,
        U32                   aBufLen) noexcept;

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

private:
    // Copy aLen bytes from aSrc into the ring starting at byte offset aStartIdx
    // (modulo ring size).  Handles wraparound silently.
    void ringCopyIn(U64 aStartIdx, const void* aSrc, U32 aLen) noexcept;

    // Copy aLen bytes from the ring starting at byte offset aStartIdx
    // (modulo ring size) into aDst.  Handles wraparound silently.
    void ringCopyOut(U64 aStartIdx, void* aDst, U32 aLen) const noexcept;

    ChannelControlBlock* m_pControl;
    std::byte*           m_pRing;
    U32                  m_uRingBytes;
    U32                  m_uNextSeq = 0U;  // writer-side sequence counter
};

} // namespace ipc
} // namespace astra

#endif // ASTRA_IPC_RING_BUFFER_HPP
