// ============================================================================
// Astra Runtime - USDT Tracepoint Macros
// include/astra/ebpf/tracepoint.h
//
// Defines custom User-Space Defined Tracepoints (USDT) for the Astra Runtime.
// These tracepoints are embedded into the binary at compile time via the
// SystemTap SDT mechanism (<sys/sdt.h>), making them visible to both:
//   - The kernel eBPF verifier (via CO-RE / uprobe attachment)
//   - The M-09 eBPF Observability module's ProbeManager
//
// DESIGN:
//   USDT tracepoints compile to a NOP on architectures that don't support
//   them, so there is zero overhead in "no observer" mode. When the eBPF
//   probe is attached, the kernel patches that NOP with a breakpoint and
//   the probe fires.
//
// USAGE:
//   Call these macros from any module. The tracepoint provider name is
//   always "astra" so that bpftrace/bcc/our own ProbeManager can find them:
//
//     ASTRA_TRACE_TASK_SPAWN(pid, name_ptr, flags, priority, 0, 0);
//
// ARGUMENT CONVENTION:
//   All tracepoints accept exactly 6 fixed-width integer or pointer args.
//   Unused args must be passed as 0. This matches the BPF CO-RE schema
//   in src/ebpf/probes/task_spawn.bpf.c.
//
// SECURITY NOTE:
//   These tracepoints operate in a closed-loop model. The ProbeManager
//   in M-09 attaches ONLY to providers named "astra". Generic Linux kernel
//   tracepoints (sched:*, syscalls:*) are explicitly out of scope for
//   Sprint 1 and must NOT be used here.
// ============================================================================
#ifndef ASTRA_EBPF_TRACEPOINT_H
#define ASTRA_EBPF_TRACEPOINT_H

// <sys/sdt.h> provides the STAP_PROBE* family of macros.
// Supplied by the systemtap-sdt-dev package (Ubuntu) or systemtap-sdt (Fedora).
#include <sys/sdt.h>

// ============================================================================
// Provider name: "astra"
// All probes share this provider so the ProbeManager can enumerate them.
// ============================================================================

// ----------------------------------------------------------------------------
// ASTRA_TRACE_TASK_SPAWN
//
// Fired immediately before the runtime spawns a new managed task/process.
//
// Args:
//   arg0  pid       (U64)  - Astra-assigned process ID
//   arg1  name_ptr  (void*)- Pointer to null-terminated task name string
//   arg2  flags     (U32)  - Spawn flags bitmask (isolation level, etc.)
//   arg3  priority  (U32)  - Scheduler priority
//   arg4  reserved0 (U64)  - Reserved, pass 0
//   arg5  reserved1 (U64)  - Reserved, pass 0
// ----------------------------------------------------------------------------
#define ASTRA_TRACE_TASK_SPAWN(pid, name_ptr, flags, priority, reserved0, reserved1) \
    STAP_PROBE6(astra, task_spawn, (pid), (name_ptr), (flags), (priority), (reserved0), (reserved1))

// ----------------------------------------------------------------------------
// ASTRA_TRACE_TASK_EXIT
//
// Fired immediately after a managed task exits or is killed.
//
// Args:
//   arg0  pid       (U64)  - Astra-assigned process ID
//   arg1  exit_code (I32)  - Exit status code
//   arg2  reason    (U32)  - Exit reason enum: 0=normal, 1=signal, 2=timeout
//   arg3  reserved0 (U64)  - Reserved, pass 0
//   arg4  reserved1 (U64)  - Reserved, pass 0
//   arg5  reserved2 (U64)  - Reserved, pass 0
// ----------------------------------------------------------------------------
#define ASTRA_TRACE_TASK_EXIT(pid, exit_code, reason, reserved0, reserved1, reserved2) \
    STAP_PROBE6(astra, task_exit, (pid), (exit_code), (reason), (reserved0), (reserved1), (reserved2))

// ----------------------------------------------------------------------------
// ASTRA_TRACE_SERVICE_EVENT
//
// Fired by the ServiceRegistry (M-01) on service lifecycle transitions.
//
// Args:
//   arg0  service_id   (U32)  - Astra ServiceId
//   arg1  module_id    (U16)  - ModuleId enum value (M-XX number)
//   arg2  event_type   (U16)  - 0=registered, 1=started, 2=stopped, 3=failed
//   arg3  name_ptr     (void*)- Pointer to null-terminated service name
//   arg4  reserved0    (U64)  - Reserved, pass 0
//   arg5  reserved1    (U64)  - Reserved, pass 0
// ----------------------------------------------------------------------------
#define ASTRA_TRACE_SERVICE_EVENT(service_id, module_id, event_type, name_ptr, reserved0, reserved1) \
    STAP_PROBE6(astra, service_event, (service_id), (module_id), (event_type), (name_ptr), (reserved0), (reserved1))

#endif // ASTRA_EBPF_TRACEPOINT_H
