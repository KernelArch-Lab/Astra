// ============================================================================
// Astra Runtime - M-02 Isolation Layer
// include/astra/isolation/seccomp_filter.h
//
// SeccompFilter: builds and installs a hardcoded PARANOID syscall allowlist
// using Linux seccomp-BPF via prctl(). Sprint 3 implementation.
//
// Sprint 3: hardcoded Paranoid allowlist (~15 syscalls).
// Sprint 4: capability-token-driven filter generation replaces this.
// ============================================================================

#pragma once

#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdexcept>
#include <vector>

namespace astra::isolation
{

// ============================================================================
// SeccompFilter
//
// Builds a BPF program that allows exactly the syscalls in the PARANOID
// profile allowlist and kills the process (SIGSYS) on any other syscall.
//
// Usage (always called inside the child process, after all namespace setup):
//
//   SeccompFilter lFilter;
//   lFilter.apply();   // throws std::runtime_error on failure
//
// Who calls this:
//   NamespaceManager::setup() — as the final step, after pivot_root().
//
// Linux primitives used:
//   prctl(PR_SET_NO_NEW_PRIVS)          — required before seccomp
//   prctl(PR_SET_SECCOMP, FILTER, prog) — loads BPF program into kernel
// ============================================================================
class SeccompFilter
{
public:

    // ------------------------------------------------------------------------
    // apply()
    //
    // Builds the BPF filter for the PARANOID profile and installs it
    // into the kernel for the calling process.
    //
    // Must be called from INSIDE the child process (after fork, before exec).
    //
    // Throws:
    //   std::runtime_error — if prctl(NO_NEW_PRIVS) fails
    //   std::runtime_error — if prctl(SET_SECCOMP) fails
    //
    // After this returns successfully, the calling process is restricted
    // to the PARANOID syscall allowlist for the rest of its lifetime.
    // ------------------------------------------------------------------------
    void apply();

private:

    // ------------------------------------------------------------------------
    // buildParanoidFilter()
    //
    // Constructs the BPF instruction list for the PARANOID profile.
    // Returns a vector of sock_filter instructions.
    //
    // The program logic:
    //   1. Load syscall number from seccomp_data.nr
    //   2. Compare against each allowed syscall — if match, ALLOW
    //   3. Default at end: KILL (SIGSYS)
    //
    // Throws:
    //   std::runtime_error — if the filter vector is empty (should never
    //                        happen, but guards against future mistakes)
    // ------------------------------------------------------------------------
    std::vector<sock_filter> buildParanoidFilter();

    // ------------------------------------------------------------------------
    // installFilter()
    //
    // Takes the built BPF instruction vector, wraps it in a sock_fprog
    // struct (what the kernel actually accepts), and calls prctl() twice:
    //   1. prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
    //   2. prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)
    //
    // Parameters:
    //   aFilter — the completed BPF instruction list from buildParanoidFilter()
    //
    // Throws:
    //   std::runtime_error — if either prctl() call fails
    // ------------------------------------------------------------------------
    void installFilter(const std::vector<sock_filter>& aFilter);
};

} // namespace astra::isolation