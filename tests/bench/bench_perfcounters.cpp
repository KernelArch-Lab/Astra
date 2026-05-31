// ============================================================================
// Astra Runtime - Paper 1 perf-counter bench (cycles / L1d / LLC / branches)
// tests/bench/bench_perfcounters.cpp
//
// Track B Sprint 8 of the Paper 1 (USENIX ATC 2027) prep work.
//
// Latency in nanoseconds is half the answer reviewers want. The other
// half is "what does the gate touch in the cache hierarchy and the
// branch predictor?". This binary opens four perf_event_open counters
// in a group and reads them across N validate() calls, reporting
// per-call cycles, L1d misses, LLC misses, branch misses.
//
// Requires CAP_PERFMON or kernel.perf_event_paranoid <= 1.  When the
// counters cannot be opened (e.g. inside a containerised CI runner),
// the binary emits "perfcounters,UNAVAILABLE,..." and exits 0 so the
// sweep does not break.
//
// CSV row format:
//   metric,pool_active,iters,sum,per_iter
// ============================================================================

#include "bench_harness.h"

#include <astra/core/capability.h>

#include <asm/unistd.h>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <vector>

using namespace astra;
using astra::core::CapabilityManager;
using astra::core::CapabilityToken;

namespace
{

long perf_event_open_(struct perf_event_attr* hw_event, pid_t pid,
                      int cpu, int group_fd, unsigned long flags)
{
    return ::syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

int openCounter(uint32_t type, uint64_t config, int groupFd)
{
    struct perf_event_attr pe{};
    pe.type           = type;
    pe.size           = sizeof(pe);
    pe.config         = config;
    pe.disabled       = (groupFd == -1) ? 1 : 0;
    pe.exclude_kernel = 1;
    pe.exclude_hv     = 1;
    pe.read_format    = PERF_FORMAT_GROUP;
    return static_cast<int>(perf_event_open_(&pe, /*pid=*/0, /*cpu=*/-1,
                                             groupFd, 0));
}

struct GroupRead
{
    uint64_t nr;
    uint64_t cycles, l1d_miss, llc_miss, branch_miss;
};

bool readGroup(int leaderFd, GroupRead& out)
{
    return ::read(leaderFd, &out, sizeof(out)) == sizeof(out);
}

} // namespace

int main()
{
    int leader = openCounter(PERF_TYPE_HARDWARE,
                             PERF_COUNT_HW_CPU_CYCLES, -1);
    if (leader < 0)
    {
        std::printf("metric,pool_active,iters,sum,per_iter\n");
        std::printf("perfcounters,UNAVAILABLE,0,0,0\n");
        std::fprintf(stderr,
            "WARN: perf_event_open failed: %s "
            "(set sysctl kernel.perf_event_paranoid=1 or use CAP_PERFMON)\n",
            std::strerror(errno));
        return 0;
    }
    int l1d = openCounter(PERF_TYPE_HW_CACHE,
                          (PERF_COUNT_HW_CACHE_L1D)
                          | (PERF_COUNT_HW_CACHE_OP_READ        << 8)
                          | (PERF_COUNT_HW_CACHE_RESULT_MISS    << 16),
                          leader);
    int llc = openCounter(PERF_TYPE_HW_CACHE,
                          (PERF_COUNT_HW_CACHE_LL)
                          | (PERF_COUNT_HW_CACHE_OP_READ        << 8)
                          | (PERF_COUNT_HW_CACHE_RESULT_MISS    << 16),
                          leader);
    int br  = openCounter(PERF_TYPE_HARDWARE,
                          PERF_COUNT_HW_BRANCH_MISSES, leader);
    if (l1d < 0 || llc < 0 || br < 0)
    {
        std::printf("metric,pool_active,iters,sum,per_iter\n");
        std::printf("perfcounters,GROUP_OPEN_FAILED,0,0,0\n");
        std::fprintf(stderr, "WARN: counter group open failed\n");
        return 0;
    }

    std::printf("metric,pool_active,iters,sum,per_iter\n");

    constexpr std::size_t kIters = 100'000;

    for (int poolActive : {16, 256, 2048, 4000})
    {
        CapabilityManager mgr;
        mgr.init(/*max=*/4096);
        std::vector<CapabilityToken> tokens;
        tokens.reserve(static_cast<std::size_t>(poolActive));
        auto root = mgr.create(Permission::IPC_SEND, 1).value();
        tokens.push_back(root);
        while (static_cast<int>(tokens.size()) < poolActive)
        {
            auto d = mgr.derive(root, Permission::IPC_SEND, 2);
            if (!d.has_value()) break;
            tokens.push_back(d.value());
        }

        // Warm-up
        for (std::size_t i = 0; i < 4096; ++i)
            (void)mgr.validate(tokens[i % tokens.size()],
                               Permission::IPC_SEND);

        ::ioctl(leader, PERF_EVENT_IOC_RESET,  PERF_IOC_FLAG_GROUP);
        ::ioctl(leader, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP);

        volatile bool sink = false;
        for (std::size_t i = 0; i < kIters; ++i)
            sink |= mgr.validate(tokens[i % tokens.size()],
                                 Permission::IPC_SEND);

        ::ioctl(leader, PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP);

        GroupRead g{};
        if (!readGroup(leader, g))
        {
            std::fprintf(stderr, "WARN: group read failed at pool=%d\n", poolActive);
            continue;
        }
        (void)sink;

        auto emit = [&](const char* m, uint64_t v) {
            std::printf("%s,%d,%zu,%llu,%.3f\n", m, poolActive, kIters,
                        static_cast<unsigned long long>(v),
                        static_cast<double>(v) / static_cast<double>(kIters));
        };
        emit("cycles",       g.cycles);
        emit("l1d_miss",     g.l1d_miss);
        emit("llc_miss",     g.llc_miss);
        emit("branch_miss",  g.branch_miss);
        std::fflush(stdout);
    }

    ::close(br);
    ::close(llc);
    ::close(l1d);
    ::close(leader);
    return 0;
}
