// ============================================================================
// Astra Runtime - M-03 IPC
// tests/ipc/test_sprint2_mpsc.cpp
//
// Tests for the MPSC write-claim protocol added in Sprint 2:
//   - fetch_add (wait-free) path for payloads <= 256 bytes
//   - CAS retry (lock-free) path for payloads  > 256 bytes
//   - SKIP sentinel handling when overcommit occurs
//   - Multiple concurrent producers, single consumer — no corruption,
//     no message loss (except under genuine ring-full conditions)
//   - Large message CAS correctness under contention
// ============================================================================

#include <astra/ipc/ChannelFactory.hpp>
#include <astra/ipc/RingBuffer.hpp>

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <vector>
#include <algorithm>

using namespace astra;
using namespace astra::ipc;

namespace
{

int g_iPassed = 0;
int g_iFailed = 0;

bool test_assert(bool aBCond, const char* aSzLabel)
{
    printf("  [%s] %s\n", aBCond ? "PASS" : "FAIL", aSzLabel);
    aBCond ? ++g_iPassed : ++g_iFailed;
    return aBCond;
}

// =========================================================================
// Test 1 — fetch_add path: two producers write small messages concurrently,
//           single consumer reads all of them with no corruption.
//
// Message sentinel: producer_id baked into every byte of the payload.
// After all producers finish, consumer drains the ring and verifies each
// message is internally consistent (all bytes equal the producer_id).
// =========================================================================
bool test_two_producers_small_messages()
{
    constexpr int  kProducers   = 2;
    constexpr int  kMsgsEach    = 30;
    constexpr U32  kPayloadSize = 64U;   // <= 256 B -> fetch_add path

    static_assert(kPayloadSize <= 256U, "must use fetch_add path");

    // Ring large enough for all messages to coexist
    const U32 kRingBytes = 8U * 1024U;
    ChannelFactory lFactory;
    auto lResult = lFactory.createChannel(300U, kRingBytes, "mpsc-small");
    if (!test_assert(lResult.has_value(), "channel created for MPSC small-message test"))
        return false;

    Channel lChannel = std::move(lResult.value());

    // Each producer gets its own RingBuffer view (same shared memory)
    std::vector<RingBuffer> lProducerRings;
    for (int lI = 0; lI < kProducers; ++lI)
    {
        lProducerRings.emplace_back(
            lChannel.control(),
            lChannel.ringBuffer(),
            lChannel.ringBufferBytes()
        );
    }

    std::atomic<int> lITotalWritten{0};
    std::vector<std::thread> lProducerThreads;

    for (int lI = 0; lI < kProducers; ++lI)
    {
        lProducerThreads.emplace_back([&, lI]() {
            U8 lPayload[kPayloadSize];
            std::memset(lPayload, static_cast<U8>(lI + 1), kPayloadSize);

            for (int lJ = 0; lJ < kMsgsEach; ++lJ)
            {
                // Retry on transient ring-full (possible under contention)
                while (true)
                {
                    auto lWr = lProducerRings[static_cast<size_t>(lI)]
                                   .write(lPayload, kPayloadSize);
                    if (lWr.has_value()) { ++lITotalWritten; break; }
                    std::this_thread::yield();
                }
            }
        });
    }

    for (auto& lThr : lProducerThreads) lThr.join();

    test_assert(lITotalWritten.load() == kProducers * kMsgsEach,
                "All producers wrote all their messages");

    // Consumer drains the ring
    RingBuffer lConsumerRing(
        lChannel.control(),
        lChannel.ringBuffer(),
        lChannel.ringBufferBytes()
    );

    int lIRead = 0;
    int lICorrupt = 0;
    U8  lOutBuf[kPayloadSize];

    while (!lConsumerRing.isEmpty())
    {
        auto lRd = lConsumerRing.read(lOutBuf, kPayloadSize);
        if (!lRd.has_value()) break;

        ++lIRead;

        // Verify payload: all bytes must equal the same value (1 or 2)
        U8 lUFirst = lOutBuf[0];
        if (lUFirst != 1U && lUFirst != 2U) { ++lICorrupt; continue; }
        for (U32 lUI = 1U; lUI < kPayloadSize; ++lUI)
        {
            if (lOutBuf[lUI] != lUFirst) { ++lICorrupt; break; }
        }
    }

    test_assert(lIRead == kProducers * kMsgsEach,
                "Consumer read exactly as many messages as were written");
    return test_assert(lICorrupt == 0,
                "No payload corruption detected in any MPSC small message");
}

// =========================================================================
// Test 2 — CAS path: two producers write large messages (> 256 B),
//           single consumer verifies no corruption.
// =========================================================================
bool test_two_producers_large_messages()
{
    constexpr int  kProducers   = 2;
    constexpr int  kMsgsEach    = 10;
    constexpr U32  kPayloadSize = 512U;  // > 256 B -> CAS path

    static_assert(kPayloadSize > 256U, "must use CAS path");

    const U32 kRingBytes = 32U * 1024U;
    ChannelFactory lFactory;
    auto lResult = lFactory.createChannel(301U, kRingBytes, "mpsc-large");
    if (!test_assert(lResult.has_value(), "channel created for MPSC large-message test"))
        return false;

    Channel lChannel = std::move(lResult.value());

    std::vector<RingBuffer> lProducerRings;
    for (int lI = 0; lI < kProducers; ++lI)
    {
        lProducerRings.emplace_back(
            lChannel.control(),
            lChannel.ringBuffer(),
            lChannel.ringBufferBytes()
        );
    }

    std::atomic<int> lITotalWritten{0};
    std::vector<std::thread> lProducerThreads;

    for (int lI = 0; lI < kProducers; ++lI)
    {
        lProducerThreads.emplace_back([&, lI]() {
            U8 lPayload[kPayloadSize];
            std::memset(lPayload, static_cast<U8>(0xA0 + lI), kPayloadSize);

            for (int lJ = 0; lJ < kMsgsEach; ++lJ)
            {
                while (true)
                {
                    auto lWr = lProducerRings[static_cast<size_t>(lI)]
                                   .write(lPayload, kPayloadSize);
                    if (lWr.has_value()) { ++lITotalWritten; break; }
                    std::this_thread::yield();
                }
            }
        });
    }

    for (auto& lThr : lProducerThreads) lThr.join();

    test_assert(lITotalWritten.load() == kProducers * kMsgsEach,
                "All producers wrote all their large messages (CAS path)");

    RingBuffer lConsumerRing(
        lChannel.control(), lChannel.ringBuffer(), lChannel.ringBufferBytes()
    );

    int lIRead = 0, lICorrupt = 0;
    U8  lOutBuf[kPayloadSize];

    while (!lConsumerRing.isEmpty())
    {
        auto lRd = lConsumerRing.read(lOutBuf, kPayloadSize);
        if (!lRd.has_value()) break;
        ++lIRead;

        U8 lUFirst = lOutBuf[0];
        if (lUFirst != 0xA0U && lUFirst != 0xA1U) { ++lICorrupt; continue; }
        for (U32 lUI = 1U; lUI < kPayloadSize; ++lUI)
            if (lOutBuf[lUI] != lUFirst) { ++lICorrupt; break; }
    }

    test_assert(lIRead == kProducers * kMsgsEach,
                "Consumer read all large messages (CAS path)");
    return test_assert(lICorrupt == 0,
                "No payload corruption in MPSC large messages");
}

// =========================================================================
// Test 3 — Mixed: small and large messages from different producers.
//           Verifies both paths coexist safely on the same ring.
// =========================================================================
bool test_mixed_small_and_large_concurrent()
{
    constexpr int  kSmallMsgs   = 20;
    constexpr int  kLargeMsgs   = 5;
    constexpr U32  kSmallPayload = 32U;
    constexpr U32  kLargePayload = 400U;

    const U32 kRingBytes = 64U * 1024U;
    ChannelFactory lFactory;
    auto lResult = lFactory.createChannel(302U, kRingBytes, "mpsc-mixed");
    if (!test_assert(lResult.has_value(), "channel created for mixed MPSC test"))
        return false;

    Channel lChannel = std::move(lResult.value());

    RingBuffer lSmallRing(lChannel.control(), lChannel.ringBuffer(), lChannel.ringBufferBytes());
    RingBuffer lLargeRing(lChannel.control(), lChannel.ringBuffer(), lChannel.ringBufferBytes());

    std::atomic<int> lISmallWritten{0};
    std::atomic<int> lILargeWritten{0};

    // Small producer thread
    std::thread lSmallProducer([&]() {
        U8 lBuf[kSmallPayload];
        std::memset(lBuf, 0x11U, kSmallPayload);
        for (int lI = 0; lI < kSmallMsgs; ++lI)
        {
            while (!lSmallRing.write(lBuf, kSmallPayload).has_value())
                std::this_thread::yield();
            ++lISmallWritten;
        }
    });

    // Large producer thread
    std::thread lLargeProducer([&]() {
        U8 lBuf[kLargePayload];
        std::memset(lBuf, 0x22U, kLargePayload);
        for (int lI = 0; lI < kLargeMsgs; ++lI)
        {
            while (!lLargeRing.write(lBuf, kLargePayload).has_value())
                std::this_thread::yield();
            ++lILargeWritten;
        }
    });

    lSmallProducer.join();
    lLargeProducer.join();

    test_assert(lISmallWritten.load() == kSmallMsgs && lILargeWritten.load() == kLargeMsgs,
                "Both small and large producers completed all writes");

    // Consumer drains everything
    RingBuffer lConsumer(lChannel.control(), lChannel.ringBuffer(), lChannel.ringBufferBytes());
    int lIRead = 0, lICorrupt = 0;
    U8  lOutBuf[kLargePayload];

    while (!lConsumer.isEmpty())
    {
        auto lPeek = lConsumer.peekNextSize();
        if (!lPeek.has_value()) break;

        auto lRd = lConsumer.read(lOutBuf, kLargePayload);
        if (!lRd.has_value()) break;
        ++lIRead;

        const U32  lUSize = lRd.value();
        const U8   lUTag  = lOutBuf[0];

        bool lBTagOk = (lUSize == kSmallPayload && lUTag == 0x11U)
                    || (lUSize == kLargePayload && lUTag == 0x22U);
        if (!lBTagOk) { ++lICorrupt; continue; }

        for (U32 lUI = 1U; lUI < lUSize; ++lUI)
            if (lOutBuf[lUI] != lUTag) { ++lICorrupt; break; }
    }

    const int lIExpected = kSmallMsgs + kLargeMsgs;
    test_assert(lIRead == lIExpected,
                "Consumer read all mixed messages (small + large)");
    return test_assert(lICorrupt == 0,
                "No payload corruption in mixed MPSC scenario");
}

// =========================================================================
// Test 4 — SKIP sentinel: force a scenario where the pre-check passes but
//           the ring is genuinely full by the time fetch_add commits.
//           Verify the reader transparently skips the sentinel and the ring
//           returns to a clean state.
// =========================================================================
bool test_skip_sentinel_handled_transparently()
{
    // Use a tiny ring: 256 bytes.  Each small msg (8+32=40 bytes) fills
    // it quickly.  Fill to 6 msgs (240 B), then try two concurrent writers
    // with a 32-byte payload — only one will fit.  The other must generate
    // a SKIP.  After draining, the ring should be fully clean.
    constexpr U32 kRingBytes   = 256U;
    constexpr U32 kPayloadSize = 32U;

    ChannelFactory lFactory;
    auto lResult = lFactory.createChannel(303U, kRingBytes, "skip-sentinel");
    if (!test_assert(lResult.has_value(), "channel created for SKIP sentinel test"))
        return false;

    Channel lChannel = std::move(lResult.value());
    RingBuffer lRing(lChannel.control(), lChannel.ringBuffer(), lChannel.ringBufferBytes());

    // Fill ring: 6 x 40 bytes = 240 bytes used (16 bytes free — not enough for another)
    U8 lFillBuf[kPayloadSize];
    std::memset(lFillBuf, 0xFFU, kPayloadSize);
    int lIFilled = 0;
    while (lRing.write(lFillBuf, kPayloadSize).has_value()) ++lIFilled;

    test_assert(lIFilled >= 1, "At least one fill message written before ring full");

    // Read exactly one message to free 40 bytes
    U8 lDrain[kPayloadSize];
    (void)lRing.read(lDrain, kPayloadSize);

    // Now two threads both try to write — the ring has exactly 40 bytes free,
    // so only one can succeed; the other triggers a SKIP or RESOURCE_EXHAUSTED.
    RingBuffer lRingA(lChannel.control(), lChannel.ringBuffer(), lChannel.ringBufferBytes());
    RingBuffer lRingB(lChannel.control(), lChannel.ringBuffer(), lChannel.ringBufferBytes());

    std::atomic<int> lISucceeded{0};
    std::atomic<int> lIFailed{0};
    std::thread lThreadA([&]() {
        U8 lBuf[kPayloadSize]; std::memset(lBuf, 0xAAU, kPayloadSize);
        if (lRingA.write(lBuf, kPayloadSize).has_value()) ++lISucceeded;
        else ++lIFailed;
    });
    std::thread lThreadB([&]() {
        U8 lBuf[kPayloadSize]; std::memset(lBuf, 0xBBU, kPayloadSize);
        if (lRingB.write(lBuf, kPayloadSize).has_value()) ++lISucceeded;
        else ++lIFailed;
    });
    lThreadA.join();
    lThreadB.join();

    // At least one succeeded, at most both could have if timing was perfect
    test_assert(lISucceeded.load() >= 1,
                "At least one concurrent small-msg write succeeded");

    // Drain the remainder — read() must not stall or return corrupted data
    RingBuffer lConsumer(lChannel.control(), lChannel.ringBuffer(), lChannel.ringBufferBytes());
    int lIReadBack = 0;
    int lICorrupt  = 0;
    U8  lOutBuf[kPayloadSize];

    while (!lConsumer.isEmpty())
    {
        auto lRd = lConsumer.read(lOutBuf, kPayloadSize);
        if (!lRd.has_value()) break;
        ++lIReadBack;
        const U8 lUFirst = lOutBuf[0];
        for (U32 lUI = 1U; lUI < kPayloadSize; ++lUI)
            if (lOutBuf[lUI] != lUFirst) ++lICorrupt;
    }

    test_assert(lIReadBack == lISucceeded.load(),
                "Drained message count matches successful writes");
    test_assert(lICorrupt == 0, "No payload corruption after SKIP-sentinel scenario");
    return test_assert(lConsumer.isEmpty(),
                "Ring is clean and empty after draining with SKIP sentinels");
}

// =========================================================================
// Test 5 — Four concurrent producers, single consumer via readWait().
//           Verifies Sprint 2 MPSC and Sprint 3 wait/notify work together.
// =========================================================================
bool test_four_producers_read_wait()
{
    constexpr int kProducers  = 4;
    constexpr int kMsgsEach   = 25;
    constexpr U32 kPayload    = 48U;    // <= 256 B

    const U32 kRingBytes = 32U * 1024U;
    ChannelFactory lFactory;
    auto lResult = lFactory.createChannel(304U, kRingBytes, "mpsc-readwait");
    if (!test_assert(lResult.has_value(), "channel created for 4-producer readWait test"))
        return false;

    Channel lChannel = std::move(lResult.value());

    std::vector<RingBuffer> lProducerRings;
    for (int lI = 0; lI < kProducers; ++lI)
        lProducerRings.emplace_back(
            lChannel.control(), lChannel.ringBuffer(), lChannel.ringBufferBytes()
        );

    const int kTotalMsgs = kProducers * kMsgsEach;
    std::atomic<int> lIWritten{0};

    // Consumer thread using readWait
    std::atomic<int> lIConsumed{0};
    std::thread lConsumer([&]() {
        RingBuffer lConsumerRing(
            lChannel.control(), lChannel.ringBuffer(), lChannel.ringBufferBytes()
        );
        U8 lBuf[kPayload];
        while (lIConsumed.load(std::memory_order_relaxed) < kTotalMsgs)
        {
            auto lRd = lConsumerRing.readWait(lBuf, kPayload);
            if (lRd.has_value()) ++lIConsumed;
        }
    });

    // Let consumer enter readWait before producers start
    std::this_thread::sleep_for(std::chrono::milliseconds(20));

    // Four producer threads
    std::vector<std::thread> lProducers;
    for (int lI = 0; lI < kProducers; ++lI)
    {
        lProducers.emplace_back([&, lI]() {
            U8 lBuf[kPayload];
            std::memset(lBuf, static_cast<U8>(lI + 1), kPayload);
            for (int lJ = 0; lJ < kMsgsEach; ++lJ)
            {
                while (true)
                {
                    auto lWr = lProducerRings[static_cast<size_t>(lI)]
                                   .writeNotify(lBuf, kPayload);
                    if (lWr.has_value()) { ++lIWritten; break; }
                    std::this_thread::yield();
                }
            }
        });
    }

    for (auto& lThr : lProducers) lThr.join();
    lConsumer.join();

    return test_assert(
        lIConsumed.load() == kTotalMsgs,
        "4-producer/1-consumer: all 100 messages consumed via readWait"
    );
}

} // namespace

int main()
{
    printf("==============================================\n");
    printf("  Astra M-03 Sprint 2 - MPSC Write-Claim     \n");
    printf("  fetch_add (small) + CAS (large) + SKIP     \n");
    printf("==============================================\n\n");

    test_two_producers_small_messages();
    test_two_producers_large_messages();
    test_mixed_small_and_large_concurrent();
    test_skip_sentinel_handled_transparently();
    test_four_producers_read_wait();

    printf("\nSummary: %d passed, %d failed\n", g_iPassed, g_iFailed);
    return (g_iFailed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
