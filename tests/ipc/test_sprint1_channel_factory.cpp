// ============================================================================
// Astra Runtime - M-03 IPC
// tests/ipc/test_sprint1_channel_factory.cpp
//
// Sprint 1 acceptance test from the IPC module brief:
//   "Channel Factory memfd_create + mmap - 2 processes see same shared memory"
// ============================================================================

#include <astra/ipc/ChannelFactory.hpp>

#include <atomic>
#include <array>
#include <cstddef>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <utility>

#include <sys/wait.h>
#include <unistd.h>

using namespace astra;
using namespace astra::ipc;

namespace
{

int g_iPassed = 0;
int g_iFailed = 0;

constexpr ChannelId TEST_CHANNEL_ID = 1;
constexpr const char* TEST_MESSAGE_PARENT_TO_CHILD = "astra-ipc-parent-to-child";
constexpr const char* TEST_MESSAGE_CHILD_TO_PARENT = "astra-ipc-child-to-parent";

void printResult(const char* aSzLabel, bool aBPassed)
{
    printf("  [%s] %s\n", aBPassed ? "PASS" : "FAIL", aSzLabel);
}

bool test_assert(bool aBCondition, const char* aSzLabel)
{
    printResult(aSzLabel, aBCondition);
    if (aBCondition)
    {
        ++g_iPassed;
    }
    else
    {
        ++g_iFailed;
    }
    return aBCondition;
}

bool test_create_channel_success()
{
    ChannelFactory lFactory;
    auto lResult = lFactory.createChannel(TEST_CHANNEL_ID, 4096, "ipc-sprint1");
    return test_assert(lResult.has_value(), "createChannel() succeeds with valid inputs");
}

bool test_control_structure_initialised()
{
    ChannelFactory lFactory;
    auto lResult = lFactory.createChannel(TEST_CHANNEL_ID + 1U, 4096, "ipc-control");
    if (!test_assert(lResult.has_value(), "channel created for control-block test"))
    {
        return false;
    }

    Channel lChannel = std::move(lResult.value());
    ChannelControlBlock* lPControl = lChannel.control();
    const bool lBInitialised =
        lPControl != nullptr
        && lPControl->m_write.m_uWriteIndex.load(std::memory_order_relaxed) == 0
        && lPControl->m_read.m_uReadIndex.load(std::memory_order_relaxed) == 0
        && lPControl->m_meta.m_uChannelId == (TEST_CHANNEL_ID + 1U)
        && lPControl->m_meta.m_uControlBytes == sizeof(ChannelControlBlock)
        && lPControl->m_meta.m_uRingBufferBytes == 4096;

    return test_assert(lBInitialised, "control structure fields are initialised");
}

bool test_mapped_size_metadata_consistent()
{
    ChannelFactory lFactory;
    auto lResult = lFactory.createChannel(TEST_CHANNEL_ID + 2U, 4096, "ipc-size");
    if (!test_assert(lResult.has_value(), "channel created for mapped-size test"))
    {
        return false;
    }

    Channel lChannel = std::move(lResult.value());
    const bool lBConsistent =
        lChannel.mappedBytes() >= sizeof(ChannelControlBlock) + 4096U
        && lChannel.control()->m_meta.m_uMappedBytes == lChannel.mappedBytes()
        && (lChannel.mappedBytes() % 4096U) == 0U;

    return test_assert(lBConsistent, "mapped size is page-aligned and matches metadata");
}

bool test_ring_buffer_zeroed()
{
    ChannelFactory lFactory;
    auto lResult = lFactory.createChannel(TEST_CHANNEL_ID + 3U, 256, "ipc-zero");
    if (!test_assert(lResult.has_value(), "channel created for zeroed-ring test"))
    {
        return false;
    }

    Channel lChannel = std::move(lResult.value());
    bool lBZeroed = true;
    for (U32 lUIdx = 0; lUIdx < lChannel.ringBufferBytes(); ++lUIdx)
    {
        if (lChannel.ringBuffer()[lUIdx] != std::byte {0})
        {
            lBZeroed = false;
            break;
        }
    }

    return test_assert(lBZeroed, "ring buffer bytes are zero-initialised");
}

bool test_default_ring_size()
{
    ChannelFactory lFactory;
    auto lResult = lFactory.createChannel(TEST_CHANNEL_ID + 4U);
    if (!test_assert(lResult.has_value(), "createChannel() works with default ring size"))
    {
        return false;
    }

    Channel lChannel = std::move(lResult.value());
    return test_assert(
        lChannel.ringBufferBytes() == ChannelFactory::DEFAULT_RING_BYTES,
        "default ring size matches ChannelFactory::DEFAULT_RING_BYTES"
    );
}

bool test_invalid_channel_id_rejected()
{
    ChannelFactory lFactory;
    auto lResult = lFactory.createChannel(0, 4096, "ipc-invalid-id");
    const bool lBRejected =
        !lResult.has_value()
        && lResult.error().code() == ErrorCode::INVALID_ARGUMENT;
    return test_assert(lBRejected, "channel ID 0 is rejected");
}

bool test_zero_ring_size_rejected()
{
    ChannelFactory lFactory;
    auto lResult = lFactory.createChannel(TEST_CHANNEL_ID + 5U, 0, "ipc-zero-ring");
    const bool lBRejected =
        !lResult.has_value()
        && lResult.error().code() == ErrorCode::INVALID_ARGUMENT;
    return test_assert(lBRejected, "zero ring-buffer size is rejected");
}

bool test_invalid_fd_rejected()
{
    ChannelFactory lFactory;
    auto lResult = lFactory.mapExistingChannel(TEST_CHANNEL_ID + 6U, -1, 8192);
    const bool lBRejected =
        !lResult.has_value()
        && lResult.error().code() == ErrorCode::INVALID_ARGUMENT;
    return test_assert(lBRejected, "mapExistingChannel() rejects invalid fd");
}

bool test_too_small_mapping_rejected()
{
    ChannelFactory lFactory;
    auto lCreate = lFactory.createChannel(TEST_CHANNEL_ID + 7U, 4096, "ipc-small-map");
    if (!test_assert(lCreate.has_value(), "channel created for too-small-mapping test"))
    {
        return false;
    }

    Channel lChannel = std::move(lCreate.value());
    auto lMapResult = lFactory.mapExistingChannel(
        TEST_CHANNEL_ID + 7U,
        lChannel.borrowFd(),
        sizeof(ChannelControlBlock) - 1U
    );

    const bool lBRejected =
        !lMapResult.has_value()
        && lMapResult.error().code() == ErrorCode::INVALID_ARGUMENT;
    return test_assert(lBRejected, "mapExistingChannel() rejects too-small mapped size");
}

bool test_move_constructor_preserves_mapping()
{
    ChannelFactory lFactory;
    auto lResult = lFactory.createChannel(TEST_CHANNEL_ID + 8U, 256, "ipc-move");
    if (!test_assert(lResult.has_value(), "channel created for move test"))
    {
        return false;
    }

    Channel lOriginal = std::move(lResult.value());
    void* lPBaseBeforeMove = lOriginal.base();
    const int lIFdBeforeMove = lOriginal.borrowFd();

    Channel lMoved(std::move(lOriginal));
    const bool lBMoveCorrect =
        !lOriginal.isValid()
        && lMoved.isValid()
        && lMoved.base() == lPBaseBeforeMove
        && lMoved.borrowFd() == lIFdBeforeMove;

    return test_assert(lBMoveCorrect, "move construction transfers channel ownership");
}

bool test_reset_invalidates_channel()
{
    ChannelFactory lFactory;
    auto lResult = lFactory.createChannel(TEST_CHANNEL_ID + 9U, 256, "ipc-reset");
    if (!test_assert(lResult.has_value(), "channel created for reset test"))
    {
        return false;
    }

    Channel lChannel = std::move(lResult.value());
    lChannel.reset();

    const bool lBResetWorks =
        !lChannel.isValid()
        && lChannel.base() == nullptr
        && lChannel.borrowFd() < 0
        && lChannel.mappedBytes() == 0;

    return test_assert(lBResetWorks, "reset() unmaps and invalidates the channel");
}

bool test_parent_to_child_shared_memory()
{
    ChannelFactory lFactory;
    auto lResult = lFactory.createChannel(TEST_CHANNEL_ID + 10U, 4096, "ipc-parent-child");
    if (!test_assert(lResult.has_value(), "channel created for parent-to-child test"))
    {
        return false;
    }

    Channel lChannel = std::move(lResult.value());
    std::memcpy(lChannel.ringBuffer(),
                TEST_MESSAGE_PARENT_TO_CHILD,
                std::strlen(TEST_MESSAGE_PARENT_TO_CHILD) + 1U);
    lChannel.control()->m_write.m_uWriteIndex.store(
        std::strlen(TEST_MESSAGE_PARENT_TO_CHILD) + 1U,
        std::memory_order_release
    );

    const pid_t lIChildPid = ::fork();
    if (!test_assert(lIChildPid >= 0, "fork() succeeds for parent-to-child test"))
    {
        return false;
    }

    if (lIChildPid == 0)
    {
        auto lMapResult = lFactory.mapExistingChannel(
            TEST_CHANNEL_ID + 10U,
            lChannel.borrowFd(),
            lChannel.mappedBytes()
        );

        if (!lMapResult.has_value())
        {
            _exit(EXIT_FAILURE);
        }

        Channel lChildChannel = std::move(lMapResult.value());
        const bool lBChildSawParentWrite =
            lChildChannel.control()->m_write.m_uWriteIndex.load(std::memory_order_acquire)
                == (std::strlen(TEST_MESSAGE_PARENT_TO_CHILD) + 1U)
            && std::strcmp(reinterpret_cast<const char*>(lChildChannel.ringBuffer()),
                           TEST_MESSAGE_PARENT_TO_CHILD) == 0;

        _exit(lBChildSawParentWrite ? EXIT_SUCCESS : EXIT_FAILURE);
    }

    int lIStatus = 0;
    if (!test_assert(::waitpid(lIChildPid, &lIStatus, 0) >= 0,
                     "waitpid() succeeds for parent-to-child test"))
    {
        return false;
    }

    return test_assert(
        WIFEXITED(lIStatus) && WEXITSTATUS(lIStatus) == 0,
        "child observed parent bytes through shared memfd mapping"
    );
}

bool test_child_to_parent_shared_memory()
{
    ChannelFactory lFactory;
    auto lChannelResult = lFactory.createChannel(TEST_CHANNEL_ID + 11U, 4096, "ipc-child-parent");
    if (!test_assert(lChannelResult.has_value(), "channel created for child-to-parent test"))
    {
        return false;
    }

    Channel lChannel = std::move(lChannelResult.value());
    ChannelControlBlock* lPControl = lChannel.control();

    const pid_t lIChildPid = ::fork();
    if (!test_assert(lIChildPid >= 0, "fork() succeeds for child-to-parent test"))
    {
        return false;
    }

    if (lIChildPid == 0)
    {
        auto lChildMapResult = lFactory.mapExistingChannel(
            TEST_CHANNEL_ID + 11U,
            lChannel.borrowFd(),
            lChannel.mappedBytes()
        );

        if (!lChildMapResult.has_value())
        {
            _exit(EXIT_FAILURE);
        }

        Channel lChildChannel = std::move(lChildMapResult.value());
        std::memcpy(lChildChannel.ringBuffer(),
                    TEST_MESSAGE_CHILD_TO_PARENT,
                    std::strlen(TEST_MESSAGE_CHILD_TO_PARENT) + 1U);
        lChildChannel.control()->m_write.m_uWriteIndex.store(
            std::strlen(TEST_MESSAGE_CHILD_TO_PARENT) + 1U,
            std::memory_order_release
        );

        _exit(EXIT_SUCCESS);
    }

    int lIStatus = 0;
    if (!test_assert(::waitpid(lIChildPid, &lIStatus, 0) >= 0,
                     "waitpid() succeeds for child-to-parent test"))
    {
        return false;
    }

    const bool lBParentSawChildWrite =
        WIFEXITED(lIStatus)
        && WEXITSTATUS(lIStatus) == 0
        && lPControl->m_write.m_uWriteIndex.load(std::memory_order_acquire)
            == (std::strlen(TEST_MESSAGE_CHILD_TO_PARENT) + 1U)
        && std::strcmp(reinterpret_cast<const char*>(lChannel.ringBuffer()),
                       TEST_MESSAGE_CHILD_TO_PARENT) == 0;

    return test_assert(lBParentSawChildWrite,
                       "parent observed child bytes through shared memfd mapping");
}

} // namespace

int main()
{
    printf("========================================\n");
    printf("  Astra M-03 Sprint 1 - Channel Factory \n");
    printf("========================================\n\n");

    test_create_channel_success();
    test_control_structure_initialised();
    test_mapped_size_metadata_consistent();
    test_ring_buffer_zeroed();
    test_default_ring_size();
    test_invalid_channel_id_rejected();
    test_zero_ring_size_rejected();
    test_invalid_fd_rejected();
    test_too_small_mapping_rejected();
    test_move_constructor_preserves_mapping();
    test_reset_invalidates_channel();
    test_parent_to_child_shared_memory();
    test_child_to_parent_shared_memory();

    printf("\nSummary: %d passed, %d failed\n", g_iPassed, g_iFailed);
    return (g_iFailed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
