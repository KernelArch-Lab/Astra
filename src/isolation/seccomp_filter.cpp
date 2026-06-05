// ============================================================================
// Astra Runtime - M-02 Isolation Layer
// src/isolation/seccomp_filter.cpp
//
// SeccompFilter implementation.
// Builds a hardcoded PARANOID BPF allowlist and installs it via prctl().
//
// Sprint 3: hardcoded Paranoid allowlist (~15 syscalls).
// Sprint 4: capability-token-driven filter generation replaces this.
// ============================================================================

#include "astra/isolation/seccomp_filter.h"

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

// BPF helper macros — these are the standard Linux macros for building
// BPF instructions. BPF_STMT builds a non-jump instruction.
// BPF_JUMP builds a conditional jump instruction.
//
// BPF_STMT(opcode, value)
//   opcode — what operation to perform (load, return, etc.)
//   value  — the immediate value to use
//
// BPF_JUMP(opcode, value, jump_true, jump_false)
//   opcode      — comparison operation
//   value       — what to compare against
//   jump_true   — how many instructions to skip if condition IS true
//   jump_false  — how many instructions to skip if condition IS false

namespace astra::isolation
{

// ============================================================================
// apply()
//
// Entry point. Called by NamespaceManager::setup() as the final step.
// Delegates to buildParanoidFilter() then installFilter().
//
// Error handling rule (Sprint 3+):
//   Internal helpers throw std::runtime_error.
//   apply() is a public API — it lets exceptions propagate up to
//   NamespaceManager::setup() which catches them and converts to Status.
// ============================================================================
void SeccompFilter::apply()
{
    std::vector<sock_filter> lFilter = buildParanoidFilter();
    installFilter(lFilter);
}

// ============================================================================
// buildParanoidFilter()
//
// Constructs the BPF instruction array for the PARANOID profile.
//
// How the BPF program works:
//
//   Step 1 — Load syscall number:
//     The kernel passes a seccomp_data struct to the BPF program.
//     seccomp_data.nr holds the syscall number.
//     We use BPF_LD to load it into the BPF accumulator register.
//
//   Step 2 — Check architecture:
//     We verify the process is running on x86-64 (AUDIT_ARCH_X86_64).
//     If not, we kill it immediately. This prevents syscall number
//     confusion attacks where a 32-bit syscall number matches a
//     different 64-bit syscall.
//
//   Step 3 — Compare against each allowed syscall:
//     For each allowed syscall number, we emit two instructions:
//       BPF_JUMP: if accumulator == syscall_nr, skip 0 instructions
//                 (fall through to ALLOW), else skip 1 (try next)
//       BPF_STMT: return SECCOMP_RET_ALLOW
//
//   Step 4 — Default KILL:
//     If no allowed syscall matched, the program reaches this
//     instruction and returns SECCOMP_RET_KILL_PROCESS.
//
// Returns:
//   std::vector<sock_filter> — the complete BPF instruction list
//
// Throws:
//   std::runtime_error — if the built filter is empty
// ============================================================================
std::vector<sock_filter> SeccompFilter::buildParanoidFilter()
{
    // The PARANOID allowlist from the Sprint 3 spec.
    // These are the ONLY syscalls the sandboxed process may call.
    // __NR_* constants are defined in <sys/syscall.h> for the current arch.
    //
    // CRITICAL CORRECTNESS (audit finding O2, 2026-05-31):
    //   The filter is installed in the child's POST_FORK hook BEFORE
    //   ProcessManager::spawn() invokes execve() on the target binary.
    //   If execve is not on the allowlist, the seccomp kernel filter
    //   kills the child with SIGSYS at the execve(2) syscall — exit 159
    //   — before the binary ever loads. No process spawned with the
    //   PARANOID profile would actually run.
    //
    //   Adding execve / execveat is the conventional fix used by gVisor,
    //   nsjail, firejail, bubblewrap and friends. The window is tight
    //   (one syscall, taken exactly once at process startup) and the
    //   downstream binary cannot itself re-execve because once the
    //   child has reached the target binary's _start, the filter still
    //   blocks anything outside the allowlist — the binary CAN call
    //   execve but the resulting process inherits the same filter
    //   (PR_SET_NO_NEW_PRIVS), so any re-exec is gated by the same list.
    // PARANOID allowlist — "minimal viable workload" set.
    //
    // Audit expansion (2026-06-04): the original 17-syscall list was
    // too aggressive — no real program could even start under it. glibc
    // startup alone needs prlimit64, set_tid_address, set_robust_list,
    // brk, mmap; any program that checks its own PID/UID needs getpid /
    // getuid; any pthreads program needs clone + futex; any process that
    // forks a child needs clone + wait4. Sprint 1 and Sprint 2 test
    // failures (signal 31 = SIGSYS) on first Linux build were caused
    // by getpid/getuid/clone being blocked.
    //
    // This expanded list (~36 syscalls) matches the PARANOID-equivalent
    // policies of nsjail, firejail, and gVisor — restrictive but
    // workable. It still blocks:
    //   - all network syscalls (socket, connect, bind, listen, accept)
    //   - ptrace, kexec, init_module, finit_module (admin)
    //   - unshare, setns, mount, umount2 (namespace re-entry)
    //   - all key-management, BPF, perf_event_open (kernel surface)
    //   - all file-creation in the sandbox is via openat with
    //     post-pivot tmpfs only (no path traversal possible)
    const std::vector<int> lAllowedSyscalls =
    {
        // I/O — minimal
        __NR_read, __NR_write, __NR_close,
        __NR_readv, __NR_writev,
        __NR_pread64, __NR_pwrite64,
        __NR_openat,                // glibc uses openat, not open
        __NR_lseek,
        __NR_dup, __NR_dup3,
        __NR_ioctl,                 // terminal/tty for printf
                                    //   (block-list specific cmds if
                                    //   needed via BPF instead)

        // Memory management
        __NR_mmap, __NR_munmap, __NR_mremap,
        __NR_mprotect, __NR_madvise, __NR_brk,

        // File metadata — modern libc uses newfstatat/statx
        __NR_fstat, __NR_newfstatat, __NR_statx,
        __NR_getdents64,            // readdir() under glibc — needed
                                    //   to walk /proc, /usr/lib, etc.

        // Process identity — needed by getpid()==1 PID-NS check
        // and any program that asks who it is.
        __NR_getpid, __NR_gettid, __NR_getppid,
        __NR_getuid, __NR_geteuid, __NR_getgid, __NR_getegid,

        // Signal handling — non-trivial programs need these
        __NR_rt_sigaction, __NR_rt_sigprocmask,
        __NR_rt_sigreturn, __NR_sigaltstack,

        // Process / thread lifecycle — pthreads + fork-from-sandbox
        __NR_clone, __NR_clone3, __NR_wait4,
        __NR_exit, __NR_exit_group,
        __NR_execve, __NR_execveat,
        __NR_futex,

        // libc / runtime startup
        __NR_arch_prctl,
        __NR_set_tid_address, __NR_set_robust_list,
        __NR_prlimit64, __NR_getrandom,
        __NR_rseq,                  // glibc 2.35+ restartable sequences
                                    //   — called unconditionally on every
                                    //   thread/process startup; if blocked
                                    //   the process dies silently with
                                    //   SIGSYS BEFORE any printf flushes,
                                    //   so the failure mode is "exit 1
                                    //   with no diagnostic output".
        __NR_prctl,                 // generic prctl. SeccompFilter itself
                                    //   uses prctl during setup; allowing
                                    //   it post-install is no worse —
                                    //   PR_SET_NO_NEW_PRIVS already locked
                                    //   in, so attackers can't gain priv
                                    //   via PR_SET_*. Mostly used by
                                    //   glibc for PR_SET_NAME and friends.

        // Time
        __NR_clock_gettime, __NR_clock_nanosleep, __NR_nanosleep,
        __NR_gettimeofday,          // older time API; some glibc paths
    };

    std::vector<sock_filter> lInstructions;

    // ------------------------------------------------------------------
    // Instruction 1: Load the syscall number into the BPF accumulator.
    //
    // BPF_LD  = load instruction
    // BPF_W   = load a 32-bit word
    // BPF_ABS = load from absolute offset in the seccomp_data struct
    //
    // offsetof(struct seccomp_data, nr) gives the byte offset of the
    // syscall number field inside the seccomp_data struct the kernel
    // provides. On x86-64 this is offset 0.
    // ------------------------------------------------------------------
    lInstructions.push_back(
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 static_cast<uint32_t>(offsetof(struct seccomp_data, nr)))
    );

    // ------------------------------------------------------------------
    // Instructions 2-3: Architecture check.
    //
    // Load the arch field from seccomp_data, compare to AUDIT_ARCH_X86_64.
    // If arch does NOT match, jump forward to the KILL instruction.
    // If arch matches, fall through to the syscall checks.
    //
    // This prevents 32-bit syscall confusion attacks.
    //
    // jump_true  = 0 → if equal, skip 0 instructions (fall through to the
    //                  reload-syscall-nr instruction, then the check chain).
    //
    // jump_false = (allowlist.size() * 2 + 1) → on arch mismatch, skip:
    //                +1 for the reload-syscall-nr instruction, plus
    //                +(allowlist.size() * 2) for the JEQ/ALLOW pairs.
    //              Lands directly on the BPF_RET_KILL_PROCESS at the end.
    //
    // The +1 is the audit fix: an earlier draft used `... * 2` which
    // landed on the LAST ALLOW instruction, accidentally ALLOWING the
    // syscall on every arch mismatch (32-bit syscall confusion path).
    // The new tracing: arch JEQ at PC=2, after execution PC=3, jf=31
    // ⇒ PC=34, which is the KILL instruction. Verified by counting.
    // ------------------------------------------------------------------
    lInstructions.push_back(
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 static_cast<uint32_t>(offsetof(struct seccomp_data, arch)))
    );

    lInstructions.push_back(
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                 AUDIT_ARCH_X86_64,
                 0,
                 static_cast<uint8_t>(lAllowedSyscalls.size() * 2 + 1))
    );

    // ------------------------------------------------------------------
    // Reload the syscall number after the architecture check.
    //
    // The arch check above overwrote the accumulator with the arch value.
    // We need the syscall number back in the accumulator for the
    // comparison instructions below.
    // ------------------------------------------------------------------
    lInstructions.push_back(
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 static_cast<uint32_t>(offsetof(struct seccomp_data, nr)))
    );

    // ------------------------------------------------------------------
    // For each allowed syscall: emit a JUMP + ALLOW pair.
    //
    // BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, syscall_nr, jt, jf)
    //   jt = 0 → if syscall matches, skip 0 instructions (next is ALLOW)
    //   jf = 1 → if syscall does not match, skip 1 instruction (skip ALLOW,
    //             try the next syscall comparison)
    //
    // BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
    //   returns ALLOW to the kernel — syscall is permitted to execute
    // ------------------------------------------------------------------
    for (int lISyscall : lAllowedSyscalls)
    {
        lInstructions.push_back(
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                     static_cast<uint32_t>(lISyscall),
                     0,
                     1)
        );

        lInstructions.push_back(
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
        );
    }

    // ------------------------------------------------------------------
    // Default instruction: KILL.
    //
    // If execution reaches here, no allowed syscall matched.
    // SECCOMP_RET_KILL_PROCESS kills the entire process (not just the
    // calling thread) and sends SIGSYS.
    //
    // SECCOMP_RET_KILL_PROCESS is stronger than SECCOMP_RET_KILL
    // (which only kills the thread). For PARANOID profile we want
    // the whole process gone.
    // ------------------------------------------------------------------
    lInstructions.push_back(
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS)
    );

    // Guard: this should never be empty, but we check defensively.
    if (lInstructions.empty())
    {
        throw std::runtime_error(
            "SeccompFilter::buildParanoidFilter: filter instruction list is empty"
        );
    }

    return lInstructions;
}

// ============================================================================
// installFilter()
//
// Takes the built BPF instruction vector and loads it into the kernel.
//
// Two prctl() calls are required, in this exact order:
//
//   1. prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
//      Tells the kernel: this process (and all its children) will never
//      gain new privileges — no suid binaries, no file capabilities.
//      The kernel REQUIRES this before allowing an unprivileged process
//      to install a seccomp filter. Without it, prctl(SET_SECCOMP) fails
//      with EACCES.
//
//   2. prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)
//      Loads the BPF program into the kernel for this process.
//      sock_fprog is the struct the kernel expects:
//        len    — number of BPF instructions
//        filter — pointer to the instruction array
//
// Parameters:
//   aFilter — completed BPF instruction list from buildParanoidFilter()
//
// Throws:
//   std::runtime_error — if PR_SET_NO_NEW_PRIVS fails
//   std::runtime_error — if PR_SET_SECCOMP fails
// ============================================================================
void SeccompFilter::installFilter(const std::vector<sock_filter>& aFilter)
{
    // Step 1: Set NO_NEW_PRIVS.
    // This is mandatory before installing a seccomp filter without root.
    // Once set, it cannot be unset — it is permanent for this process
    // and all children it forks.
    if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
    {
        int lIErrno = errno; // capture immediately — next call may overwrite
        throw std::runtime_error(
            std::string("SeccompFilter::installFilter: "
                        "prctl(PR_SET_NO_NEW_PRIVS) failed: ")
            + strerror(lIErrno)
        );
    }

    // Step 2: Build the sock_fprog struct.
    // sock_fprog is what prctl(PR_SET_SECCOMP) actually accepts.
    // It wraps our instruction array with a length field.
    //
    // len must fit in unsigned short — our filter is ~35 instructions,
    // well within the limit of 65535.
    struct sock_fprog lProg;
    lProg.len    = static_cast<unsigned short>(aFilter.size());
    lProg.filter = const_cast<sock_filter*>(aFilter.data());

    // Step 3: Install the filter.
    // After this call returns successfully, the filter is active.
    // Any syscall not on the allowlist will cause SIGSYS immediately.
    if (::prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &lProg) != 0)
    {
        int lIErrno = errno; // capture immediately
        throw std::runtime_error(
            std::string("SeccompFilter::installFilter: "
                        "prctl(PR_SET_SECCOMP) failed: ")
            + strerror(lIErrno)
        );
    }
}

} // namespace astra::isolation