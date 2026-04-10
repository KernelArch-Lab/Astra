// ============================================================================
// Astra Runtime - M-03 IPC Sprint 1 Live Demo
// tests/ipc/demo_ipc_live.cpp
//
// This is NOT a pass/fail test — it's a live demonstration that shows
// inter-process communication happening in real time via shared memory.
//
// What you'll see:
//   1. Parent creates a shared memory channel (memfd + mmap)
//   2. Parent forks a child process
//   3. Parent writes numbered messages into the ring buffer
//   4. Child reads them from the SAME physical memory (different virtual mapping)
//   5. Child writes an acknowledgement back
//   6. Parent reads the acknowledgement
//
// Both processes print timestamped, coloured output so you can watch
// the communication happen live in your terminal.
// ============================================================================

#include <astra/ipc/ChannelFactory.hpp>
#include <astra/ipc/Types.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>

#include <sys/wait.h>
#include <unistd.h>

using namespace astra;
using namespace astra::ipc;

// ============================================================================
// ANSI colour codes for readable terminal output
// ============================================================================
static constexpr const char* COL_RESET   = "\033[0m";
static constexpr const char* COL_BOLD    = "\033[1m";
static constexpr const char* COL_GREEN   = "\033[32m";
static constexpr const char* COL_BLUE    = "\033[34m";
static constexpr const char* COL_MAGENTA = "\033[35m";
static constexpr const char* COL_CYAN    = "\033[36m";
static constexpr const char* COL_YELLOW  = "\033[33m";
static constexpr const char* COL_RED     = "\033[31m";

// ============================================================================
// Shared message protocol (written into the ring buffer)
//
// Layout:
//   [4 bytes: message length (U32)]
//   [N bytes: null-terminated string]
//
// The write index in the control block tracks the total bytes written.
// The read index tracks total bytes consumed.
// ============================================================================
struct MessageHeader
{
    U32 m_uLength;  // Length of the string payload (including null terminator)
};

static void writeMessage(Channel& aChannel, const char* aSzMsg)
{
    const U32 lUMsgLen = static_cast<U32>(std::strlen(aSzMsg)) + 1U;
    const U32 lUTotalLen = static_cast<U32>(sizeof(MessageHeader)) + lUMsgLen;

    U64 lUWriteIdx = aChannel.control()->m_write.m_uWriteIndex.load(std::memory_order_acquire);

    // Write the header
    std::byte* lPDest = aChannel.ringBuffer() + lUWriteIdx;
    MessageHeader lHdr{lUMsgLen};
    std::memcpy(lPDest, &lHdr, sizeof(lHdr));

    // Write the payload
    std::memcpy(lPDest + sizeof(lHdr), aSzMsg, lUMsgLen);

    // Publish the write (release so the reader sees both header + payload)
    aChannel.control()->m_write.m_uWriteIndex.store(
        lUWriteIdx + lUTotalLen, std::memory_order_release
    );
}

static bool readMessage(Channel& aChannel, char* aBuf, U32 aUBufSize, U64& aUReadIdx)
{
    U64 lUWriteIdx = aChannel.control()->m_write.m_uWriteIndex.load(std::memory_order_acquire);

    if (aUReadIdx >= lUWriteIdx)
    {
        return false; // Nothing new to read
    }

    // Read the header
    const std::byte* lPSrc = aChannel.ringBuffer() + aUReadIdx;
    MessageHeader lHdr{};
    std::memcpy(&lHdr, lPSrc, sizeof(lHdr));

    // Read the payload
    U32 lUCopyLen = (lHdr.m_uLength < aUBufSize) ? lHdr.m_uLength : (aUBufSize - 1U);
    std::memcpy(aBuf, lPSrc + sizeof(lHdr), lUCopyLen);
    aBuf[lUCopyLen] = '\0';

    aUReadIdx += sizeof(MessageHeader) + lHdr.m_uLength;

    // Update the read index so the other side can see our progress
    aChannel.control()->m_read.m_uReadIndex.store(aUReadIdx, std::memory_order_release);

    return true;
}

// ============================================================================
// Demo messages that the parent will send to the child
// ============================================================================
static const char* g_arrMessages[] = {
    "Hello from parent! This is message #1",
    "Shared memory IPC is working — message #2",
    "memfd_create + mmap(MAP_SHARED) = zero-copy IPC — message #3",
    "No kernel context switches needed for data transfer — message #4",
    "Final message #5 — channel communication complete!",
};
static constexpr int g_iNumMessages = 5;

// ============================================================================
// Child process entry point
// ============================================================================
static int childProcess(ChannelFactory& aFactory, int aIParentFd, SizeT aUMappedBytes)
{
    // Map the SAME shared memory from the parent's fd
    auto lMapResult = aFactory.mapExistingChannel(42, aIParentFd, aUMappedBytes);
    if (!lMapResult.has_value())
    {
        fprintf(stderr, "%s[CHILD] ERROR: Failed to map parent channel%s\n", COL_RED, COL_RESET);
        return EXIT_FAILURE;
    }

    Channel lChannel = std::move(lMapResult.value());

    fprintf(stderr, "\n%s%s[CHILD  PID %d] Mapped parent's shared memory (fd=%d, %zu bytes)%s\n",
            COL_BOLD, COL_CYAN, getpid(), aIParentFd, aUMappedBytes, COL_RESET);
    fprintf(stderr, "%s[CHILD] Waiting for messages from parent...%s\n\n", COL_CYAN, COL_RESET);

    // Give parent a moment to start writing
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    char lSzBuf[512];
    U64 lUReadIdx = 0;
    int lIReceived = 0;

    // Read all messages from parent
    while (lIReceived < g_iNumMessages)
    {
        if (readMessage(lChannel, lSzBuf, sizeof(lSzBuf), lUReadIdx))
        {
            ++lIReceived;
            fprintf(stderr, "  %s[CHILD  <--] Received: \"%s\"%s\n",
                    COL_GREEN, lSzBuf, COL_RESET);
            fflush(stderr);
        }
        else
        {
            // Spin-wait briefly (real code would use futex or eventfd)
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }

    // Write acknowledgement back to parent via the SAME channel
    fprintf(stderr, "\n  %s[CHILD  -->] Writing acknowledgement back to parent...%s\n", COL_CYAN, COL_RESET);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    writeMessage(lChannel, "ACK: All 5 messages received successfully! Child signing off.");

    fprintf(stderr, "  %s[CHILD] Done. Exiting.%s\n\n", COL_CYAN, COL_RESET);

    return EXIT_SUCCESS;
}

// ============================================================================
// main — Parent process
// ============================================================================
int main()
{
    fprintf(stderr, "\n%s%s", COL_BOLD, COL_MAGENTA);
    fprintf(stderr, "╔══════════════════════════════════════════════════════════════╗\n");
    fprintf(stderr, "║       Astra M-03 IPC Sprint 1 — Live Channel Demo          ║\n");
    fprintf(stderr, "║   Two processes communicating via shared memory (memfd)     ║\n");
    fprintf(stderr, "╚══════════════════════════════════════════════════════════════╝%s\n\n", COL_RESET);

    // ---- Step 1: Create the channel ----
    ChannelFactory lFactory;
    fprintf(stderr, "%s[PARENT PID %d] Creating shared memory channel...%s\n", COL_YELLOW, getpid(), COL_RESET);

    auto lResult = lFactory.createChannel(42, 16384, "astra-ipc-demo");
    if (!lResult.has_value())
    {
        fprintf(stderr, "%sERROR: %s%s\n", COL_RED,
                std::string(lResult.error().message()).c_str(), COL_RESET);
        return EXIT_FAILURE;
    }

    Channel lChannel = std::move(lResult.value());
    fprintf(stderr, "%s[PARENT] Channel created:%s\n", COL_YELLOW, COL_RESET);
    fprintf(stderr, "           Channel ID    : %u\n", lChannel.id());
    fprintf(stderr, "           Mapped bytes   : %zu\n", lChannel.mappedBytes());
    fprintf(stderr, "           Ring buffer    : %u bytes\n", lChannel.ringBufferBytes());
    fprintf(stderr, "           Control block  : %zu bytes (3 cache lines)\n", sizeof(ChannelControlBlock));
    fprintf(stderr, "           memfd          : fd %d\n", lChannel.borrowFd());

    // ---- Step 2: Fork child ----
    fprintf(stderr, "\n%s[PARENT] Forking child process...%s\n", COL_YELLOW, COL_RESET);

    const int lIFd = lChannel.borrowFd();
    const SizeT lUMapped = lChannel.mappedBytes();
    const pid_t lIChild = ::fork();

    if (lIChild < 0)
    {
        perror("fork");
        return EXIT_FAILURE;
    }

    if (lIChild == 0)
    {
        // Child process
        return childProcess(lFactory, lIFd, lUMapped);
    }

    // ---- Step 3: Parent sends messages ----
    fprintf(stderr, "%s[PARENT] Child spawned (PID %d). Sending %d messages...%s\n\n",
            COL_YELLOW, lIChild, g_iNumMessages, COL_RESET);

    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    for (int lI = 0; lI < g_iNumMessages; ++lI)
    {
        writeMessage(lChannel, g_arrMessages[lI]);
        fprintf(stderr, "  %s[PARENT -->] Sent: \"%s\"%s\n",
                COL_BLUE, g_arrMessages[lI], COL_RESET);
        fflush(stderr);

        // Stagger sends so you can watch them arrive one by one
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }

    // ---- Step 4: Wait for child's acknowledgement ----
    fprintf(stderr, "\n%s[PARENT] All messages sent. Waiting for child ACK...%s\n", COL_YELLOW, COL_RESET);

    // Wait for child to finish
    int lIStatus = 0;
    ::waitpid(lIChild, &lIStatus, 0);

    // Read the child's acknowledgement
    char lSzAck[512];

    // Child wrote using writeMessage which advances the write index.
    // We need to read from where the parent left off writing (child's messages start there).
    // Since parent wrote 5 messages and child wrote 1 ack after, let's find it:
    // Use the parent's write position as our read start for the ack
    U64 lUParentWriteEnd = 0;
    for (int lI = 0; lI < g_iNumMessages; ++lI)
    {
        lUParentWriteEnd += sizeof(MessageHeader) + static_cast<U32>(std::strlen(g_arrMessages[lI])) + 1U;
    }

    U64 lUAckStart = lUParentWriteEnd;
    if (readMessage(lChannel, lSzAck, sizeof(lSzAck), lUAckStart))
    {
        fprintf(stderr, "  %s%s[PARENT <--] Received ACK: \"%s\"%s\n",
                COL_BOLD, COL_GREEN, lSzAck, COL_RESET);
    }

    // ---- Summary ----
    fprintf(stderr, "\n%s%s", COL_BOLD, COL_MAGENTA);
    fprintf(stderr, "╔══════════════════════════════════════════════════════════════╗\n");
    fprintf(stderr, "║                    Demo Complete!                            ║\n");
    fprintf(stderr, "║                                                              ║\n");
    fprintf(stderr, "║  ✓ Shared memory channel created via memfd_create           ║\n");
    fprintf(stderr, "║  ✓ Parent wrote 5 messages into the ring buffer             ║\n");
    fprintf(stderr, "║  ✓ Child mapped the SAME memory and read all 5              ║\n");
    fprintf(stderr, "║  ✓ Child wrote acknowledgement back through same channel    ║\n");
    fprintf(stderr, "║  ✓ Zero-copy, zero-syscall data transfer between processes  ║\n");
    fprintf(stderr, "╚══════════════════════════════════════════════════════════════╝%s\n\n", COL_RESET);

    bool lBChildOk = WIFEXITED(lIStatus) && WEXITSTATUS(lIStatus) == 0;
    return lBChildOk ? EXIT_SUCCESS : EXIT_FAILURE;
}
