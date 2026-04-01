// ============================================================================
// Astra Runtime - M-03 Channel Factory
// include/astra/ipc/ChannelFactory.hpp
//
// Sprint 1 deliverable from the IPC module brief:
//   - allocate a channel with memfd_create + ftruncate + mmap(MAP_SHARED)
//   - initialise the shared control structure
//   - allow another process to map the same memfd and observe shared bytes
// ============================================================================
#ifndef ASTRA_IPC_CHANNEL_FACTORY_HPP
#define ASTRA_IPC_CHANNEL_FACTORY_HPP

#include <astra/common/result.h>
#include <astra/ipc/Types.hpp>

#include <cstddef>
#include <string>
#include <string_view>

namespace astra
{
namespace ipc
{

class UniqueFd
{
public:
    UniqueFd() noexcept = default;
    explicit UniqueFd(int aIFd) noexcept;
    ~UniqueFd() noexcept;

    UniqueFd(const UniqueFd&) = delete;
    UniqueFd& operator=(const UniqueFd&) = delete;

    UniqueFd(UniqueFd&& aOther) noexcept;
    UniqueFd& operator=(UniqueFd&& aOther) noexcept;

    [[nodiscard]] int get() const noexcept;
    [[nodiscard]] bool isValid() const noexcept;
    [[nodiscard]] int release() noexcept;
    void reset(int aIFd = -1) noexcept;

private:
    int m_iFd = -1;
};

class Channel
{
public:
    Channel() noexcept = default;
    Channel(ChannelId aUChannelId, UniqueFd aFd, void* aPBase, SizeT aUMappedBytes) noexcept;
    ~Channel() noexcept;

    Channel(const Channel&) = delete;
    Channel& operator=(const Channel&) = delete;

    Channel(Channel&& aOther) noexcept;
    Channel& operator=(Channel&& aOther) noexcept;

    [[nodiscard]] bool isValid() const noexcept;
    [[nodiscard]] ChannelId id() const noexcept;
    [[nodiscard]] int borrowFd() const noexcept;
    [[nodiscard]] void* base() const noexcept;
    [[nodiscard]] SizeT mappedBytes() const noexcept;
    [[nodiscard]] ChannelControlBlock* control() const noexcept;
    [[nodiscard]] std::byte* ringBuffer() const noexcept;
    [[nodiscard]] U32 ringBufferBytes() const noexcept;

    void reset() noexcept;

private:
    ChannelId m_uChannelId = 0;
    UniqueFd  m_fd;
    void*     m_pBase = nullptr;
    SizeT     m_uMappedBytes = 0;
};

class ChannelFactory
{
public:
    static constexpr SizeT DEFAULT_RING_BYTES = 2U * 1024U * 1024U;

    [[nodiscard]] Result<Channel> createChannel(
        ChannelId        aUChannelId,
        SizeT            aURingBufferBytes = DEFAULT_RING_BYTES,
        std::string_view aSzName = "astra-ipc"
    ) const;

    [[nodiscard]] Result<Channel> mapExistingChannel(
        ChannelId aUChannelId,
        int       aIFd,
        SizeT     aUMappedBytes
    ) const;

private:
    [[nodiscard]] Result<Channel> mapOwnedFd(
        ChannelId aUChannelId,
        UniqueFd  aFd,
        SizeT     aUMappedBytes
    ) const;
};

} // namespace ipc
} // namespace astra

#endif // ASTRA_IPC_CHANNEL_FACTORY_HPP
