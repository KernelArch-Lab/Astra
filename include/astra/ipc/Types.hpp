// ============================================================================
// Astra Runtime - M-03 IPC Types
// include/astra/ipc/Types.hpp
//
// Sprint 1 scope:
//   - Channel control structure in shared memory
//   - Ring buffer region description
//   - Fixed 3-cache-line control layout from the IPC design brief
// ============================================================================
#ifndef ASTRA_IPC_TYPES_HPP
#define ASTRA_IPC_TYPES_HPP

#include <astra/common/types.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>

namespace astra
{
namespace ipc
{

inline constexpr SizeT CACHE_LINE_SIZE = 64;

struct alignas(CACHE_LINE_SIZE) ChannelControlLineWrite
{
    // Committed write index — readers observe this to know what is safe to read.
    std::atomic<U64> m_uWriteIndex {0};

    // Claim index — writers advance this first to reserve their slot (MPSC coordination).
    //   <= 256 B payload : claimed via fetch_add  (wait-free, single atomic op)
    //    > 256 B payload : claimed via CAS loop   (lock-free, bounded retries)
    // In SPSC mode write_index == write_claim_index at all times.
    std::atomic<U64> m_uWriteClaimIndex {0};

    std::array<std::byte, CACHE_LINE_SIZE - 2 * sizeof(std::atomic<U64>)> m_arrPadding {};
};

struct alignas(CACHE_LINE_SIZE) ChannelControlLineRead
{
    std::atomic<U64> m_uReadIndex {0};
    std::array<std::byte, CACHE_LINE_SIZE - sizeof(std::atomic<U64>)> m_arrPadding {};
};

struct alignas(CACHE_LINE_SIZE) ChannelControlLineMeta
{
    U32 m_uChannelId = 0;
    U32 m_uControlBytes = 0;
    U32 m_uRingBufferBytes = 0;
    U32 m_uMappedBytes = 0;
    std::array<std::byte, CACHE_LINE_SIZE - (4 * sizeof(U32))> m_arrPadding {};
};

struct alignas(CACHE_LINE_SIZE) ChannelControlBlock
{
    ChannelControlLineWrite m_write;
    ChannelControlLineRead  m_read;
    ChannelControlLineMeta  m_meta;
};

static_assert(sizeof(ChannelControlBlock) == 3 * CACHE_LINE_SIZE,
              "ChannelControlBlock must stay exactly 3 cache lines");

} // namespace ipc
} // namespace astra

#endif // ASTRA_IPC_TYPES_HPP
