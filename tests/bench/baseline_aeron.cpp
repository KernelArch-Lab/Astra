// ============================================================================
// Astra Runtime - Paper 1 baseline: Aeron IPC RTT
// tests/bench/baseline_aeron.cpp
//
// Track B Sprint 6 of the Paper 1 (USENIX ATC 2027) prep work.
//
// Aeron is the prior-art IPC primitive Paper 1 has to beat (or
// match within Y%). We use AeronCpp's IpcPublication / Subscription
// over the shared Media Driver, with a tight echo loop on a second
// thread.
//
// Build-skip behaviour: if Aeron's headers are not available, this
// emits "aeron,SKIPPED,...". Sprint 7's sweep detects that and omits
// Aeron from the figure (with a footnote in the paper).
//
// Why we use the C++ binding: matching language eliminates
// thread-scheduling and JIT-warmup variance from the comparison.
// Aeron's own published 250 ns number is C++.
// ============================================================================

#include "bench_harness.h"

#if !__has_include(<Aeron.h>)

#include <cstdio>
int main()
{
    astra_bench::printCsvHeader();
    std::printf("aeron,SKIPPED,0,0,0,0,0,0\n");
    std::fprintf(stderr, "WARN: AeronCpp not installed; build with "
                         "-DAERON_DIR=/path/to/aeron-cpp/build/main if you want "
                         "this baseline\n");
    return 0;
}

#else // AeronCpp present

#include <Aeron.h>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

namespace
{

constexpr const char* kIpcChannel  = "aeron:ipc";
constexpr int32_t     kStreamReq   = 1001;
constexpr int32_t     kStreamReply = 1002;

void runPayload(std::size_t payload, std::size_t iters, double tscPerNs)
{
    aeron::Context ctx;
    auto aer = aeron::Aeron::connect(ctx);

    auto subReqId   = aer->addSubscription(kIpcChannel, kStreamReq);
    auto pubReqId   = aer->addPublication (kIpcChannel, kStreamReq);
    auto subReplyId = aer->addSubscription(kIpcChannel, kStreamReply);
    auto pubReplyId = aer->addPublication (kIpcChannel, kStreamReply);

    auto subReq   = aer->findSubscription(subReqId);
    auto pubReq   = aer->findPublication (pubReqId);
    auto subReply = aer->findSubscription(subReplyId);
    auto pubReply = aer->findPublication (pubReplyId);

    while (!subReq || !pubReq || !subReply || !pubReply)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        subReq   = aer->findSubscription(subReqId);
        pubReq   = aer->findPublication (pubReqId);
        subReply = aer->findSubscription(subReplyId);
        pubReply = aer->findPublication (pubReplyId);
    }

    std::vector<uint8_t> tx(payload, 'A');
    std::vector<uint8_t> rx(payload, 0);

    std::atomic<bool> stop{false};
    std::thread echo([&]() {
        aeron::concurrent::AtomicBuffer scratch(rx.data(),
                                                static_cast<std::int32_t>(rx.size()));
        aeron::FragmentAssembler asm_(
            [&](aeron::AtomicBuffer& buf, std::int32_t off, std::int32_t len,
                aeron::Header& /*hdr*/) {
                std::memcpy(scratch.buffer(), buf.buffer() + off,
                            static_cast<std::size_t>(len));
                while (pubReply->offer(scratch, 0, len) < 0L)
                {
                    if (stop.load(std::memory_order_acquire)) return;
                }
            });
        while (!stop.load(std::memory_order_acquire))
            subReq->poll(asm_.handler(), 16);
    });

    aeron::concurrent::AtomicBuffer txBuf(tx.data(),
                                          static_cast<std::int32_t>(tx.size()));
    bool gotReply = false;
    aeron::FragmentAssembler asmReply(
        [&](aeron::AtomicBuffer& /*buf*/, std::int32_t /*off*/,
            std::int32_t /*len*/, aeron::Header& /*hdr*/) { gotReply = true; });

    auto roundTrip = [&]() {
        gotReply = false;
        while (pubReq->offer(txBuf, 0, static_cast<std::int32_t>(tx.size())) < 0L) {}
        while (!gotReply) subReply->poll(asmReply.handler(), 1);
    };

    for (std::size_t i = 0; i < astra_bench::kWarmup; ++i) roundTrip();

    std::vector<uint64_t> deltas;
    deltas.reserve(iters);
    for (std::size_t i = 0; i < iters; ++i)
    {
        const uint64_t t0 = astra_bench::now();
        roundTrip();
        const uint64_t t1 = astra_bench::now();
        if (t1 > t0) deltas.push_back(t1 - t0);
    }

    auto s = astra_bench::summarise(deltas, tscPerNs);
    astra_bench::printCsvRow("aeron", payload, s);

    stop.store(true, std::memory_order_release);
    echo.join();
}

} // namespace

int main()
{
    const double tscPerNs = astra_bench::tscPerNs();
    astra_bench::printCsvHeader();
    for (std::size_t p : astra_bench::kPayloads)
    {
        runPayload(p, astra_bench::kIters, tscPerNs);
    }
    return 0;
}

#endif // __has_include(<Aeron.h>)
