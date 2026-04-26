# Astra Runtime

> Astra is a userspace runtime that gates every zero-copy memfd IPC
> channel on stock Linux through unforgeable capability tokens with
> epoch-based cascading revocation, achieving sub-microsecond
> validated message delivery without kernel modifications. We aim to
> show that capability-mediated IPC can match raw shared-memory
> throughput while supporting global revocation in O(1) — a
> combination not available in seL4 (no Linux), gVisor (no
> capabilities), or Firecracker (no IPC model).

**C++23 · x86-64 Assembly · Linux only · pre-alpha**

For the full picture — architecture, per-module status, build
graph, integration patterns — read [docs/PROJECT_GUIDE.md](docs/PROJECT_GUIDE.md).
For the publication roadmap, read [docs/PUBLICATION_STRATEGY.md](docs/PUBLICATION_STRATEGY.md).

---

## Honest status

Six modules are real and tested today; the other fifteen are
scaffolding (a directory under `src/` with a placeholder README)
waiting for their implementation phase.

| | Module | Built today |
|---|---|---|
| L1 | M-01 Core | capability tokens, IService, ServiceRegistry, EventBus, ProcessManager, HookRegistry |
| L1 | M-21 ASM Core | C++ stubs for `ct_compare`, `secure_wipe`, `rdrand64`, `lfence`, `cache_flush`, `stack_canary` (NASM ports planned) |
| L2 | M-02 Isolation | USER + PID + MOUNT namespaces, `pivot_root` with private propagation, tmpfs sandbox, ProfileEngine |
| L2 | M-03 IPC | `memfd_create` + `mmap(MAP_SHARED)` channels, two-phase MPSC ring buffer, futex `wait`/`notify` |
| L2 | M-06 Allocator | 4-tier pool routing, poison patterns, double-free detection, capability-gated, audit hooks |
| L2 | M-09 eBPF | libbpf + USDT probe loader, `epoll`-based ring-buffer poller (one `task_spawn` probe shipping) |

Everything else (M-04, M-05, M-07, M-08, M-10, M-11, M-12, M-13, M-14,
M-15, M-16, M-17, M-18, M-19, M-20) is reserved scaffolding. The
[Future work](#future-work) section below is explicit about what is
*not* built — feature claims in this README cover only the BUILT row.

---

## Building

Requirements:
- Linux x86-64 (Fedora / Ubuntu 24.04 / Arch)
- GCC 13+ or Clang 17+
- CMake 3.28+
- NASM 2.16+ (for the M-21 ASM Core ports)
- libbpf, libelf, clang (for M-09 eBPF probes)

One-shot build + test driver:

```bash
./scripts/compile-astra.sh                  # full build + ctest
./scripts/compile-astra.sh -R Sprint2       # filter ctest by regex
ASTRA_BUILD_TYPE=Release ./scripts/compile-astra.sh
```

Or manually:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j"$(nproc)"
ctest --test-dir build --output-on-failure
```

Build presets in [CMakePresets.json](CMakePresets.json):
`debug`, `release`, `sanitize`, `tsan`, `msan`.

---

## Architecture (built modules only)

Six layers, twenty-one modules. The table below describes only what
*currently runs*; planned-but-unbuilt modules are listed separately.

| Layer | Built today |
|---|---|
| 1 — Core | Capability model, service registry, process manager (M-01); ASM crypto stubs (M-21) |
| 2 — Services | Namespace + tmpfs sandbox (M-02); zero-copy IPC ring buffer (M-03); pool allocator with audit (M-06); libbpf observability (M-09) |
| 3 — Security | reserved (M-04 Checkpoint, M-05 Replay, M-12 Verify) |
| 4 — Intelligence | reserved (M-08 AI, M-16 HAL, M-17 Profiler) |
| 5 — Application | reserved (M-07 Job Engine, M-10 WASM, M-11 AQL, M-15 Consensus) |
| 6 — Infrastructure | reserved (M-13 Net, M-14 VFS, M-18 Crypto, M-19 Vtime, M-20 Loader) |

Cross-layer integration — how the built modules wire into M-01's
`HookRegistry`, `EventBus`, and `CapabilityManager` — is documented
in [docs/PROJECT_GUIDE.md](docs/PROJECT_GUIDE.md) with mermaid
diagrams.

---

## Naming convention

All C++ code uses Hungarian-style prefixes:

- **Member fields**: `m_` + type letter + Name (e.g. `m_iFd`,
  `m_szName`, `m_vThreads`)
- **Local variables**: `l` + type letter + Name (e.g. `lIRetVal`,
  `lSzPath`)
- **Function arguments**: `a` + type letter + Name (e.g. `aIFd`,
  `aSzPath`)
- **Globals**: `g_` + Name (e.g. `g_logIpc`)

Type letters: `i` int, `u` unsigned, `b` bool, `e` enum, `p`
pointer, `sz` string, `v` vector, `fd` file descriptor, `arr`
array.

---

## Future work

These pillars appeared in earlier descriptions of the project and
are reserved as future work. They are *not* claimed as features of
the current codebase. When a reviewer or contributor asks about
them, point at this section.

| Pillar | Status | Where it will land |
|---|---|---|
| Deterministic forensic replay | Not started | M-04 (Checkpoint) + M-05 (Replay), Phase 5 |
| Formal verification | Not started — `formal/` is empty | Track B's CBMC bounded-model-check of capability monotonicity (Q4 2026) is the first real proof; broader verification is M-12 (Phase 9) |
| AI anomaly detection | Not started — `ai_pipeline/` is empty | M-08 (Phase 6). One narrow slice (learned-allocator size-class predictor) is scoped for year 1 |
| Confidential computing (TDX/SEV/CCA) | Reserved as M-23 | Phase 4 add-on, planned for 2027 |
| Post-quantum hybrid crypto (ML-DSA / ML-KEM) | Reserved | M-18 + M-21, planned for 2027 |
| Hardware memory tagging (MTE / LAM) | Reserved | M-06 extension, planned for 2027 |
| WASM Component Model | Reserved as M-10 | Phase 4, deferred to year 2 |
| AI agent sandboxing | Reserved as M-22 | Phase add-on, planned for 2027 |

The publication strategy in [docs/PUBLICATION_STRATEGY.md](docs/PUBLICATION_STRATEGY.md)
explains which of these we plan to ship in the next 12 months and
which papers depend on which.

---

## License

TBD
