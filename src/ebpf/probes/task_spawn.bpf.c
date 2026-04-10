// ============================================================================
// Astra Runtime - M-09 eBPF Observability Microservice
// src/ebpf/probes/task_spawn.bpf.c
//
// CO-RE eBPF probe for the Astra "task_spawn" USDT tracepoint.
//
// WHAT THIS FILE IS:
//   This is the kernel-side half of the M-09 observability pipeline.
//   It is compiled by clang with -target bpf at BUILD TIME into
//   task_spawn.bpf.o, which is then loaded at RUNTIME by ProbeManager.
//   The CO-RE (Compile Once - Run Everywhere) approach means we embed
//   BTF type information so the BPF verifier can relocate field offsets
//   across different kernel versions automatically.
//
// WHAT THIS PROBE DOES:
//   This probe attaches to the "astra:task_spawn" USDT tracepoint defined
//   in include/astra/ebpf/tracepoint.h. Every time the Astra Runtime
//   calls ASTRA_TRACE_TASK_SPAWN(...) in userspace, this BPF program fires
//   in the kernel, captures the arguments, packs them into an EbpfEventHeader,
//   and submits them to the shared ring buffer for userspace consumption.
//
// WHY RING BUFFER OVER PERF EVENT ARRAY:
//   bpf_ringbuf_reserve / bpf_ringbuf_submit is preferred over
//   bpf_perf_event_output for three reasons:
//     1. Memory efficiency: the ring buffer is shared across all CPUs,
//        whereas perf event arrays allocate one buffer per CPU core.
//     2. Ordering: ring buffer submissions are globally ordered.
//     3. Back-pressure: bpf_ringbuf_reserve returns NULL when full (vs.
//        silently dropping events in the perf path).
//
// COMPILATION:
//   This file is compiled by the CMake build step in src/ebpf/CMakeLists.txt:
//     clang -g -O2 -target bpf -D__TARGET_ARCH_x86 \
//           -I/usr/include/bpf \
//           -c task_spawn.bpf.c -o task_spawn.bpf.o
// ============================================================================

// vmlinux.h provides all kernel type definitions for CO-RE.
// Generated per-machine by: bpftool btf dump file /sys/kernel/btf/vmlinux format c
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>    // BPF helper macros (bpf_ktime_get_ns, etc.)
#include <bpf/bpf_tracing.h>    // SEC() macro for USDT and kprobe attachment
#include <bpf/bpf_core_read.h>  // BPF_CORE_READ for CO-RE field access

// ============================================================================
// Event type constants — must stay in sync with EbpfEventType in ebpf_service.h
// ============================================================================
#define ASTRA_EVENT_TASK_SPAWN   1

// ============================================================================
// TaskSpawnEvent
//
// The full event layout written into the ring buffer for each task_spawn.
// The EbpfEventHeader (first 16 bytes) must EXACTLY match the C++ struct in
// include/astra/ebpf/ebpf_service.h — the BPF verifier does not enforce this,
// so it is our responsibility.
//
// Byte layout:
//   [0..7]   timestamp_ns  — u64 CLOCK_MONOTONIC_COARSE
//   [8..9]   event_type    — u16 = ASTRA_EVENT_TASK_SPAWN (1)
//   [10..13] source_pid    — u32 kernel PID
//   [14..15] event_size    — u16 sizeof(TaskSpawnEvent)
//   [16..17] flags         — u16 reserved, always 0 in Sprint 1
//   [18..21] astra_pid     — u64 Astra-assigned process ID (arg0)
//   [26..33] spawn_flags   — u32 flags bitmask from ASTRA_TRACE_TASK_SPAWN
//   [34..37] priority      — u32 scheduler priority
// ============================================================================
struct TaskSpawnEvent
{
    // --- EbpfEventHeader fields (must match C++ layout exactly) ---
    __u64 timestamp_ns;
    __u16 event_type;
    __u32 source_pid;
    __u16 event_size;
    __u16 flags;

    // --- Payload: task_spawn-specific fields ---
    __u64 astra_pid;      // arg0: Astra process ID passed to ASTRA_TRACE_TASK_SPAWN
    __u64 name_ptr;       // arg1: raw pointer to task name (not dereferenced in Sprint 1)
    __u32 spawn_flags;    // arg2: spawn flags bitmask
    __u32 priority;       // arg3: scheduler priority
} __attribute__((packed));

// ============================================================================
// BPF Maps
//
// SHARED_RINGBUF: the ring buffer that carries events to userspace.
// The userspace ProbeManager looks up this map by name "shared_ringbuf"
// to obtain the file descriptor passed to ring_buffer__new().
//
// Size: 256 KB (64 pages * 4096). Sufficient for Sprint 1 burst rates.
// ============================================================================
struct
{
    __uint(type,        BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);    // 256 KB
} shared_ringbuf SEC(".maps");

// ============================================================================
// task_spawn_handler
//
// Attaches to the "astra:task_spawn" USDT tracepoint via uprobe.
//
// USDT probes in BPF use the uprobe mechanism under the hood. libbpf
// resolves the USDT note section in the Astra binary and patches the
// attachment address automatically when we call bpf_program__attach_usdt().
//
// Arguments arrive via the pt_regs context. The STAP_PROBE6 macro in
// <sys/sdt.h> stores the 6 args in registers following the SystemTap
// calling convention, which libbpf's PT_REGS_PARM macros decode.
// ============================================================================
SEC("usdt/astra:task_spawn")
int task_spawn_handler(struct pt_regs* ctx)
{
    // -----------------------------------------------------------------
    // Step 1: Reserve space in the ring buffer.
    // If the buffer is full, bpf_ringbuf_reserve returns NULL.
    // We must check and bail out — this is how back-pressure works.
    // -----------------------------------------------------------------
    struct TaskSpawnEvent* lPEvent = bpf_ringbuf_reserve(
        &shared_ringbuf,
        sizeof(struct TaskSpawnEvent),
        0   // flags: must be 0
    );
    if (!lPEvent)
    {
        // Ring buffer full — event dropped. The userspace poller will
        // see a gap in sequence numbers (future Sprint 2 feature).
        return 0;
    }

    // -----------------------------------------------------------------
    // Step 2: Populate the EbpfEventHeader fields.
    // bpf_ktime_get_ns() returns CLOCK_MONOTONIC nanoseconds.
    // bpf_get_current_pid_tgid() returns (tgid << 32 | pid).
    // We want the PID (lower 32 bits). Cast explicitly — no C-style casts.
    // -----------------------------------------------------------------
    lPEvent->timestamp_ns = bpf_ktime_get_ns();
    lPEvent->event_type   = ASTRA_EVENT_TASK_SPAWN;
    lPEvent->source_pid   = (u32)(bpf_get_current_pid_tgid() & 0xFFFFFFFF);
    lPEvent->event_size   = (u16)sizeof(struct TaskSpawnEvent);
    lPEvent->flags        = 0;  // reserved; Sprint 1 always 0

    // -----------------------------------------------------------------
    // Step 3: Extract the USDT arguments from the pt_regs context.
    // PT_REGS_PARM1..PT_REGS_PARM4 correspond to arg0..arg3 from
    // ASTRA_TRACE_TASK_SPAWN(pid, name_ptr, flags, priority, r0, r1).
    // -----------------------------------------------------------------
    lPEvent->astra_pid   = (u64)PT_REGS_PARM1(ctx);
    lPEvent->name_ptr    = (u64)PT_REGS_PARM2(ctx);   // raw ptr, logged only
    lPEvent->spawn_flags = (u32)PT_REGS_PARM3(ctx);
    lPEvent->priority    = (u32)PT_REGS_PARM4(ctx);

    // -----------------------------------------------------------------
    // Step 4: Submit. This makes the event visible to userspace atomically.
    // After submit, we must NOT touch lPEvent — it is now owned by the kernel.
    // -----------------------------------------------------------------
    bpf_ringbuf_submit(lPEvent, 0);

    return 0;
}

// Required BPF program license declaration.
// GPLv2 required for helper functions that access kernel internals.
char LICENSE[] SEC("license") = "GPL";
