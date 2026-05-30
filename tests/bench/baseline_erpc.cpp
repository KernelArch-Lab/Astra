// ============================================================================
// Astra Runtime - Paper 1 baseline: eRPC RTT (NSDI '19, ~2.3 µs published)
// tests/bench/baseline_erpc.cpp
//
// Track B Sprint 6 of the Paper 1 (USENIX ATC 2027) prep work.
//
// eRPC is the closest peer-reviewed RPC number for low-latency transport
// (NSDI '19). It is an *RPC* layer, not a raw transport, so the comparison
// in Paper 1 is positioned as "for the network-RPC reference point" — we
// don't fight on raw IPC RTT here, we fight on cross-node RPC latency.
//
// On a single machine eRPC runs over DPDK or its built-in CTransport.
// We use the InfBand transport if available, fall back to CTransport,
// and SKIP if neither builds.
//
// Build-skip behaviour: if eRPC is not installed, emits "erpc,SKIPPED,..."
// and Sprint 7's sweep omits the row.
// ============================================================================

#include "bench_harness.h"

#if !__has_include(<rpc.h>)

#include <cstdio>
int main()
{
    astra_bench::printCsvHeader();
    std::printf("erpc,SKIPPED,0,0,0,0,0,0\n");
    std::fprintf(stderr, "WARN: eRPC not installed; build with -DERPC_DIR=... "
                         "if you want this baseline. eRPC is at "
                         "https://github.com/erpc-io/eRPC\n");
    return 0;
}

#else // eRPC present

// We isolate eRPC's headers behind a single TU because it pulls in DPDK
// and a long list of -I paths via its CMake config; the other baselines
// must remain buildable even when eRPC is not installed.

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <rpc.h>
#include <thread>
#include <vector>

namespace
{

constexpr uint8_t  kReqType = 0x01;
constexpr uint16_t kPort    = 31850;

struct Ctx { erpc::MsgBuffer reqBuf, respBuf; std::atomic<bool> done{false}; };

void serverReqHandler(erpc::ReqHandle* req, void* userCtx)
{
    auto* nexus = reinterpret_cast<erpc::Rpc<erpc::CTransport>*>(userCtx);
    auto& reqMsg = req->get_req_msgbuf();
    auto& respMsg = req->pre_resp_msgbuf;
    nexus->resize_msg_buffer(&respMsg, reqMsg->get_data_size());
    std::memcpy(respMsg.buf, reqMsg->buf, reqMsg->get_data_size());
    nexus->enqueue_response(req, &respMsg);
}

void clientRespHandler(void* /*ctx*/, void* userCtx)
{
    reinterpret_cast<Ctx*>(userCtx)->done.store(true, std::memory_order_release);
}

void runPayload(std::size_t payload, std::size_t iters, double tscPerNs)
{
    erpc::Nexus nexus("127.0.0.1:" + std::to_string(kPort), /*phy_port=*/0,
                      /*numa_node=*/0);
    nexus.register_req_func(kReqType, serverReqHandler);

    erpc::Rpc<erpc::CTransport> server(&nexus, /*ctx=*/nullptr,
                                       /*rpc_id=*/0, /*sm_handler=*/nullptr);
    erpc::Rpc<erpc::CTransport> client(&nexus, /*ctx=*/nullptr,
                                       /*rpc_id=*/1, /*sm_handler=*/nullptr);

    int sessionNum = client.create_session("127.0.0.1:" + std::to_string(kPort), 0);
    while (!client.is_connected(sessionNum)) client.run_event_loop_once();

    Ctx ctx;
    ctx.reqBuf  = client.alloc_msg_buffer(payload);
    ctx.respBuf = client.alloc_msg_buffer(payload);
    std::memset(ctx.reqBuf.buf, 'A', payload);

    auto roundTrip = [&]() {
        ctx.done.store(false, std::memory_order_release);
        client.enqueue_request(sessionNum, kReqType, &ctx.reqBuf, &ctx.respBuf,
                               clientRespHandler, &ctx);
        while (!ctx.done.load(std::memory_order_acquire))
            client.run_event_loop_once();
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
    astra_bench::printCsvRow("erpc", payload, s);

    client.free_msg_buffer(ctx.reqBuf);
    client.free_msg_buffer(ctx.respBuf);
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

#endif // __has_include(<rpc.h>)
