// ============================================================================
// Astra Runtime - Paper 1 baseline: io_uring SQE/CQE round trip
// tests/bench/baseline_io_uring.cpp
//
// Track B Sprint 6 of the Paper 1 (USENIX ATC 2027) prep work.
//
// io_uring is *the* head-to-head for Astra. Both share the design template
// of mmap'd ring buffers with futex-style notification — the prior-art
// survey called this out explicitly. The fair comparison is:
//
//   "How fast can two threads exchange one payload through the kernel
//    using io_uring's SQE/CQE rings, vs through Astra's memfd ring with
//    the capability gate enabled?"
//
// We submit IORING_OP_WRITE on one side of a pipe and IORING_OP_READ on
// the other (single submission pair), peek the CQE, and reap. SQPOLL is
// disabled in the default run because it adds a busy kernel thread that
// distorts steady-state percentiles; we provide a flag for the
// SQPOLL-on case as a sanity check.
//
// Build-skip behaviour: if liburing is not installed, this file emits a
// single "io_uring,SKIPPED,..." CSV row and exits 0. The Sprint 7 sweep
// script keys off that to omit the comparison from the figure.
// ============================================================================

#include "bench_harness.h"

#if !__has_include(<liburing.h>)

#include <cstdio>
int main()
{
    astra_bench::printCsvHeader();
    std::printf("io_uring,SKIPPED,0,0,0,0,0,0\n");
    std::fprintf(stderr, "WARN: liburing not installed; install liburing-devel "
                         "(Fedora) or liburing-dev (Debian/Ubuntu) and rebuild\n");
    return 0;
}

#else // liburing present

#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <liburing.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace
{

struct Rings
{
    struct io_uring sender;
    struct io_uring receiver;
};

// Submission-queue polling trades a syscall per submit for a dedicated
// kernel thread draining the SQ — PER RING, and this harness opens two.
// That is a good trade on a host with spare cores and a bad one without:
// on a 4-core laptop with two cores handed to isolcpus, the pollers
// contend with the benchmark threads for what little is left. Measured
// there, SQPOLL made io_uring SLOWER (8.5 us vs 6.2 us p99 at 256 B) and
// could stall outright on the idle/wakeup handshake.
//
// So it is opt-in, not default: set ASTRA_IOURING_SQPOLL=1 on a machine
// with cores to spare. Whichever mode runs is reported, because the two
// configurations are not comparable and the paper must say which it used.
bool g_bSqpoll = false;

void initRing(struct io_uring& r, unsigned int entries)
{
    const char* pSqpoll = std::getenv("ASTRA_IOURING_SQPOLL");
    if (pSqpoll != nullptr && pSqpoll[0] == '1')
    {
        struct io_uring_params params;
        std::memset(&params, 0, sizeof(params));
        params.flags = IORING_SETUP_SQPOLL;
        params.sq_thread_idle = 100;   // ms before the poller sleeps

        int rcPoll = io_uring_queue_init_params(entries, &r, &params);
        if (rcPoll == 0)
        {
            g_bSqpoll = true;
            return;
        }
        std::fprintf(stderr,
                     "WARN: ASTRA_IOURING_SQPOLL=1 but SQPOLL init failed "
                     "(%s) — using syscall-per-submit\n",
                     std::strerror(-rcPoll));
    }

    int rc = io_uring_queue_init(entries, &r, /*flags=*/0);
    if (rc < 0)
    {
        std::fprintf(stderr, "io_uring_queue_init: %s\n",
                     std::strerror(-rc));
        std::exit(1);
    }
}

// Submit one IORING_OP_WRITE for `len` bytes, wait for its CQE, and
// return the number of bytes actually written (or -errno).
int submitWriteSync(struct io_uring& r, int fd, const void* buf,
                    unsigned len)
{
    struct io_uring_sqe* sqe = io_uring_get_sqe(&r);
    io_uring_prep_write(sqe, fd, buf, len, /*offset=*/0);
    io_uring_submit(&r);

    struct io_uring_cqe* cqe = nullptr;
    int rc = io_uring_wait_cqe(&r, &cqe);
    if (rc < 0) return rc;
    int res = cqe->res;
    io_uring_cqe_seen(&r, cqe);
    return res;
}

int submitReadSync(struct io_uring& r, int fd, void* buf, unsigned len)
{
    struct io_uring_sqe* sqe = io_uring_get_sqe(&r);
    io_uring_prep_read(sqe, fd, buf, len, /*offset=*/0);
    io_uring_submit(&r);

    struct io_uring_cqe* cqe = nullptr;
    int rc = io_uring_wait_cqe(&r, &cqe);
    if (rc < 0) return rc;
    int res = cqe->res;
    io_uring_cqe_seen(&r, cqe);
    return res;
}

void runPayload(std::size_t payload, std::size_t iters, double tscPerNs)
{
    int down[2];   // tx -> echoer
    int up[2];     // echoer -> tx
    if (::pipe(down) != 0 || ::pipe(up) != 0)
    {
        std::fprintf(stderr, "pipe(): %s\n", std::strerror(errno));
        std::exit(1);
    }

    std::vector<char> tx(payload, 'A');
    std::vector<char> rx(payload, 0);

    struct io_uring sendRing, echoRing;
    initRing(sendRing, /*entries=*/8);
    initRing(echoRing, /*entries=*/8);

    std::atomic<bool> ready{false};
    std::thread echo([&]() {
        astra_bench::pinSelf(1);
        std::vector<char> buf(payload, 0);
        ready.store(true, std::memory_order_release);
        for (std::size_t i = 0; i < iters + astra_bench::kWarmup; ++i)
        {
            std::size_t got = 0;
            while (got < payload)
            {
                int n = submitReadSync(echoRing, down[0],
                                       buf.data() + got,
                                       static_cast<unsigned>(payload - got));
                if (n <= 0) return;
                got += static_cast<std::size_t>(n);
            }
            std::size_t put = 0;
            while (put < payload)
            {
                int n = submitWriteSync(echoRing, up[1],
                                        buf.data() + put,
                                        static_cast<unsigned>(payload - put));
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
            int n = submitWriteSync(sendRing, down[1],
                                    tx.data() + put,
                                    static_cast<unsigned>(payload - put));
            if (n <= 0) std::exit(2);
            put += static_cast<std::size_t>(n);
        }
        std::size_t got = 0;
        while (got < payload)
        {
            int n = submitReadSync(sendRing, up[0],
                                   rx.data() + got,
                                   static_cast<unsigned>(payload - got));
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
    astra_bench::printCsvRow("io_uring", payload, s);

    ::close(down[1]);
    ::close(up[1]);
    echo.join();
    ::close(down[0]);
    ::close(up[0]);
    io_uring_queue_exit(&sendRing);
    io_uring_queue_exit(&echoRing);
}

} // namespace

int main()
{
    astra_bench::reportPinning("baseline_io_uring");
    astra_bench::pinSelf(0);
    const double tscPerNs = astra_bench::tscPerNs();
    astra_bench::printCsvHeader();
    for (std::size_t p : astra_bench::kPayloads)
    {
        runPayload(p, astra_bench::kIters, tscPerNs);
    }
    // State the mode on stderr so the sweep log records which io_uring
    // configuration produced these rows — the two are not comparable.
    std::fprintf(stderr, "io_uring mode: %s\n",
                 g_bSqpoll ? "SQPOLL (kernel-polled submission queue)"
                           : "syscall-per-submit (SQPOLL unavailable)");
    return 0;
}

#endif // __has_include(<liburing.h>)
