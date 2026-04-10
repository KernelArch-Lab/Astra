// ============================================================================
// Astra Runtime - M-03 Channel Factory
// src/ipc/ChannelFactory.cpp
// ============================================================================

#include <astra/ipc/ChannelFactory.hpp>

#include <astra/common/log.h>

#include <cerrno>
#include <cstring>
#include <new>
#include <string>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

namespace astra
{
namespace ipc
{

namespace
{

constexpr const char* LOG_TAG = "ipc_factory";

[[nodiscard]] Error makeErrnoError(ErrorCode aECode, const char* aSzContext)
{
    return makeError(
        aECode,
        ErrorCategory::IPC,
        std::string(aSzContext) + ": " + std::strerror(errno)
    );
}

[[nodiscard]] SizeT pageSize()
{
    long lIPageSize = ::sysconf(_SC_PAGESIZE);
    return (lIPageSize > 0) ? static_cast<SizeT>(lIPageSize) : static_cast<SizeT>(4096);
}

[[nodiscard]] SizeT roundUpToPage(SizeT aUValue)
{
    const SizeT lUPageSize = pageSize();
    const SizeT lURemainder = aUValue % lUPageSize;
    return (lURemainder == 0) ? aUValue : (aUValue + (lUPageSize - lURemainder));
}

[[nodiscard]] int createMemfd(const std::string& aSzName)
{
#ifdef SYS_memfd_create
    return static_cast<int>(::syscall(SYS_memfd_create, aSzName.c_str(), MFD_CLOEXEC));
#else
    errno = ENOSYS;
    return -1;
#endif
}

} // namespace

UniqueFd::UniqueFd(int aIFd) noexcept
    : m_iFd(aIFd)
{
}

UniqueFd::~UniqueFd() noexcept
{
    reset();
}

UniqueFd::UniqueFd(UniqueFd&& aOther) noexcept
    : m_iFd(aOther.release())
{
}

UniqueFd& UniqueFd::operator=(UniqueFd&& aOther) noexcept
{
    if (this != &aOther)
    {
        reset(aOther.release());
    }
    return *this;
}

int UniqueFd::get() const noexcept
{
    return m_iFd;
}

bool UniqueFd::isValid() const noexcept
{
    return m_iFd >= 0;
}

int UniqueFd::release() noexcept
{
    const int lIFd = m_iFd;
    m_iFd = -1;
    return lIFd;
}

void UniqueFd::reset(int aIFd) noexcept
{
    if (m_iFd >= 0)
    {
        ::close(m_iFd);
    }
    m_iFd = aIFd;
}

Channel::Channel(ChannelId aUChannelId, UniqueFd aFd, void* aPBase, SizeT aUMappedBytes) noexcept
    : m_uChannelId(aUChannelId)
    , m_fd(std::move(aFd))
    , m_pBase(aPBase)
    , m_uMappedBytes(aUMappedBytes)
{
}

Channel::~Channel() noexcept
{
    reset();
}

Channel::Channel(Channel&& aOther) noexcept
    : m_uChannelId(aOther.m_uChannelId)
    , m_fd(std::move(aOther.m_fd))
    , m_pBase(aOther.m_pBase)
    , m_uMappedBytes(aOther.m_uMappedBytes)
{
    aOther.m_uChannelId = 0;
    aOther.m_pBase = nullptr;
    aOther.m_uMappedBytes = 0;
}

Channel& Channel::operator=(Channel&& aOther) noexcept
{
    if (this != &aOther)
    {
        reset();
        m_uChannelId = aOther.m_uChannelId;
        m_fd = std::move(aOther.m_fd);
        m_pBase = aOther.m_pBase;
        m_uMappedBytes = aOther.m_uMappedBytes;

        aOther.m_uChannelId = 0;
        aOther.m_pBase = nullptr;
        aOther.m_uMappedBytes = 0;
    }
    return *this;
}

bool Channel::isValid() const noexcept
{
    return m_fd.isValid() && m_pBase != nullptr && m_uMappedBytes >= sizeof(ChannelControlBlock);
}

ChannelId Channel::id() const noexcept
{
    return m_uChannelId;
}

int Channel::borrowFd() const noexcept
{
    return m_fd.get();
}

void* Channel::base() const noexcept
{
    return m_pBase;
}

SizeT Channel::mappedBytes() const noexcept
{
    return m_uMappedBytes;
}

ChannelControlBlock* Channel::control() const noexcept
{
    return static_cast<ChannelControlBlock*>(m_pBase);
}

std::byte* Channel::ringBuffer() const noexcept
{
    return static_cast<std::byte*>(m_pBase) + sizeof(ChannelControlBlock);
}

U32 Channel::ringBufferBytes() const noexcept
{
    return isValid() ? control()->m_meta.m_uRingBufferBytes : 0U;
}

void Channel::reset() noexcept
{
    if (m_pBase != nullptr && m_uMappedBytes > 0)
    {
        ::munmap(m_pBase, m_uMappedBytes);
    }

    m_pBase = nullptr;
    m_uMappedBytes = 0;
    m_uChannelId = 0;
    m_fd.reset();
}

Result<Channel> ChannelFactory::createChannel(
    ChannelId        aUChannelId,
    SizeT            aURingBufferBytes,
    std::string_view aSzName
) const
{
    if (aUChannelId == 0)
    {
        return astra::unexpected(makeError(
            ErrorCode::INVALID_ARGUMENT,
            ErrorCategory::IPC,
            "Channel ID must be non-zero"
        ));
    }

    if (aURingBufferBytes == 0)
    {
        return astra::unexpected(makeError(
            ErrorCode::INVALID_ARGUMENT,
            ErrorCategory::IPC,
            "Ring buffer bytes must be greater than zero"
        ));
    }

    const SizeT lUMappedBytes = roundUpToPage(sizeof(ChannelControlBlock) + aURingBufferBytes);
    if (lUMappedBytes > static_cast<SizeT>(UINT32_MAX))
    {
        return astra::unexpected(makeError(
            ErrorCode::INVALID_ARGUMENT,
            ErrorCategory::IPC,
            "Mapped channel size exceeds Sprint 1 metadata limits"
        ));
    }

    std::string lSzName(aSzName);
    if (lSzName.empty())
    {
        lSzName = "astra-ipc";
    }

    UniqueFd lFd(createMemfd(lSzName));
    if (!lFd.isValid())
    {
        return astra::unexpected(makeErrnoError(ErrorCode::SYSCALL_FAILED, "memfd_create failed"));
    }

    if (::ftruncate(lFd.get(), static_cast<off_t>(lUMappedBytes)) != 0)
    {
        return astra::unexpected(makeErrnoError(ErrorCode::SYSCALL_FAILED, "ftruncate failed"));
    }

    auto lResult = mapOwnedFd(aUChannelId, std::move(lFd), lUMappedBytes);
    if (!lResult.has_value())
    {
        return lResult;
    }

    Channel& lChannel = lResult.value();
    ChannelControlBlock* lPControl = lChannel.control();
    std::construct_at(lPControl);
    lPControl->m_write.m_uWriteIndex.store(0, std::memory_order_relaxed);
    lPControl->m_read.m_uReadIndex.store(0, std::memory_order_relaxed);
    lPControl->m_meta.m_uChannelId = aUChannelId;
    lPControl->m_meta.m_uControlBytes = static_cast<U32>(sizeof(ChannelControlBlock));
    lPControl->m_meta.m_uRingBufferBytes = static_cast<U32>(aURingBufferBytes);
    lPControl->m_meta.m_uMappedBytes = static_cast<U32>(lUMappedBytes);

    std::memset(lChannel.ringBuffer(), 0, aURingBufferBytes);

    ASTRA_LOG_INFO(LOG_TAG, "Created channel %u with %u-byte ring buffer (%zu mapped bytes)",
                   aUChannelId,
                   static_cast<unsigned>(aURingBufferBytes),
                   lUMappedBytes);

    return lResult;
}

Result<Channel> ChannelFactory::mapExistingChannel(
    ChannelId aUChannelId,
    int       aIFd,
    SizeT     aUMappedBytes
) const
{
    if (aIFd < 0)
    {
        return astra::unexpected(makeError(
            ErrorCode::INVALID_ARGUMENT,
            ErrorCategory::IPC,
            "Cannot map channel from invalid fd"
        ));
    }

    const int lIDupFd = ::fcntl(aIFd, F_DUPFD_CLOEXEC, 0);
    if (lIDupFd < 0)
    {
        return astra::unexpected(makeErrnoError(ErrorCode::SYSCALL_FAILED, "fcntl(F_DUPFD_CLOEXEC) failed"));
    }

    return mapOwnedFd(aUChannelId, UniqueFd(lIDupFd), aUMappedBytes);
}

Result<Channel> ChannelFactory::mapOwnedFd(
    ChannelId aUChannelId,
    UniqueFd  aFd,
    SizeT     aUMappedBytes
) const
{
    if (!aFd.isValid())
    {
        return astra::unexpected(makeError(
            ErrorCode::INVALID_ARGUMENT,
            ErrorCategory::IPC,
            "ChannelFactory received an invalid memfd"
        ));
    }

    if (aUMappedBytes < sizeof(ChannelControlBlock))
    {
        return astra::unexpected(makeError(
            ErrorCode::INVALID_ARGUMENT,
            ErrorCategory::IPC,
            "Mapped size must include the control block"
        ));
    }

    void* lPMapping = ::mmap(nullptr,
                             aUMappedBytes,
                             PROT_READ | PROT_WRITE,
                             MAP_SHARED,
                             aFd.get(),
                             0);

    if (lPMapping == MAP_FAILED)
    {
        return astra::unexpected(makeErrnoError(ErrorCode::SYSCALL_FAILED, "mmap failed"));
    }

    return Channel(aUChannelId, std::move(aFd), lPMapping, aUMappedBytes);
}

} // namespace ipc
} // namespace astra
