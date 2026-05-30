// ============================================================================
// Astra Runtime - Paper 1 baseline: socketpair(AF_UNIX, SOCK_STREAM) RTT
// tests/bench/baseline_socketpair.cpp
//
// Track B Sprint 6 of the Paper 1 (USENIX ATC 2027) prep work.
//
// Same shape as baseline_pipe but over a Unix-domain stream socket. Two
// flavours of "the obvious answer": pipe is buffered FIFO, socketpair
// adds protocol overhead. Numbers should bracket each other.
//
// gVisor's KVM platform IPC fall-back path looks roughly like this; we
// cite the socketpair number as the "what gVisor would do" reference,
// not as a head-to-head against gVisor itself.
// ============================================================================

#include "bench_harness.h"

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace
{

void runPayload(std::size_t payload, std::size_t iters, double tscPerNs)
{
    int fds[2];
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
    {
        std::fprintf(stderr, "socketpair() failed: %s\n", std::strerror(errno));
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
                ssize_t n = ::recv(fds[1], buf.data() + got, payload - got, 0);
                if (n <= 0) return;
                got += static_cast<std::size_t>(n);
            }
            std::size_t put = 0;
            while (put < payload)
            {
                ssize_t n = ::send(fds[1], buf.data() + put, payload - put, 0);
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
            ssize_t n = ::send(fds[0], tx.data() + put, payload - put, 0);
            if (n <= 0) std::exit(2);
            put += static_cast<std::size_t>(n);
        }
        std::size_t got = 0;
        while (got < payload)
        {
            ssize_t n = ::recv(fds[0], rx.data() + got, payload - got, 0);
            if (n <= 0) std::exit(2);
            got += static_cast<std::size_t>(n);
        }
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
    astra_bench::printCsvRow("socketpair", payload, s);

    ::shutdown(fds[0], SHUT_RDWR);
    echo.join();
    ::close(fds[0]);
    ::close(fds[1]);
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
