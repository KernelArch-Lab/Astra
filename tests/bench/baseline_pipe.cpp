// ============================================================================
// Astra Runtime - Paper 1 baseline: pipe(2) IPC RTT
// tests/bench/baseline_pipe.cpp
//
// Track B Sprint 6 of the Paper 1 (USENIX ATC 2027) prep work.
//
// The "sysadmin's first answer" baseline. Two unidirectional pipes, two
// threads, one round trip per iter. This is the syscall-bound floor;
// Astra (memfd + mmap shared ring) should beat it by an order of
// magnitude. Reported here so reviewers see the scale of the win.
//
// We deliberately use blocking read/write — io_uring's edge is async,
// not single-RTT, and we have a separate baseline for it.
// ============================================================================

#include "bench_harness.h"

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <unistd.h>
#include <vector>

namespace
{

void runPayload(std::size_t payload, std::size_t iters, double tscPerNs)
{
    int aDown[2];   // parent -> child
    int aUp[2];     // child -> parent
    if (::pipe(aDown) != 0 || ::pipe(aUp) != 0)
    {
        std::fprintf(stderr, "pipe() failed: %s\n", std::strerror(errno));
        std::exit(1);
    }

    std::vector<char> tx(payload, 'A');
    std::vector<char> rx(payload, 0);

    std::atomic<bool> ready{false};
    std::thread echo([&]() {
        std::vector<char> buf(payload, 0);
        ready.store(true, std::memory_order_release);
        for (std::size_t i = 0; i < iters + astra_bench::kWarmup; ++i)
        {
            std::size_t got = 0;
            while (got < payload)
            {
                ssize_t n = ::read(aDown[0], buf.data() + got, payload - got);
                if (n <= 0) return;
                got += static_cast<std::size_t>(n);
            }
            std::size_t put = 0;
            while (put < payload)
            {
                ssize_t n = ::write(aUp[1], buf.data() + put, payload - put);
                if (n <= 0) return;
                put += static_cast<std::size_t>(n);
            }
        }
    });

    while (!ready.load(std::memory_order_acquire)) std::this_thread::yield();

    auto roundTrip = [&]() {
        std::size_t put = 0;
        while (put < payload)
        {
            ssize_t n = ::write(aDown[1], tx.data() + put, payload - put);
            if (n <= 0) std::exit(2);
            put += static_cast<std::size_t>(n);
        }
        std::size_t got = 0;
        while (got < payload)
        {
            ssize_t n = ::read(aUp[0], rx.data() + got, payload - got);
            if (n <= 0) std::exit(2);
            got += static_cast<std::size_t>(n);
        }
    };

    // Warm-up
    for (std::size_t i = 0; i < astra_bench::kWarmup; ++i) roundTrip();

    // Measured
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
    astra_bench::printCsvRow("pipe", payload, s);

    ::close(aDown[1]);
    ::close(aUp[1]);
    echo.join();
    ::close(aDown[0]);
    ::close(aUp[0]);
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
