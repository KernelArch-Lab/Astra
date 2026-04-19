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
