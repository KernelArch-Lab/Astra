# Astra Runtime

A modular, capability-based, cybersecurity-hardened, AI-augmented userspace runtime for Linux.

**C++23 | x86-64 Assembly | Linux Only**

## Status

Pre-alpha. Architecture-defining phase. No module is production-ready.

## Building

Requirements:
- Linux x86-64 (Ubuntu 24.04 LTS recommended)
- GCC 13+ or Clang 17+
- CMake 3.28+
- NASM 2.16+ (for Assembly modules)

```bash
cmake --preset debug
cmake --build build/debug
```

Run:
```bash
./build/debug/astra_runtime --help
./build/debug/astra_runtime --name my-instance -v
```

Build presets:
- `debug` - Debug build with assertions
- `release` - Optimised with hardening flags
- `sanitize` - ASan + UBSan enabled
- `tsan` - ThreadSanitizer for race detection
- `msan` - MemorySanitizer for uninitialised reads

## Architecture

21 modules across 6 layers. See `docs/` for full technical documentation.

| Layer | Name | Modules |
|-------|------|---------|
| 6 | Infrastructure | Network, Filesystem, Crypto, Time, Module Loader |
| 5 | Application | Job Engine, WASM Sandbox, Query Language, Consensus, Profiler |
| 4 | Intelligence | AI Scheduler, Learned Allocator, Anomaly Detector, HAL |
| 3 | Security | Intrusion Detection, Threat Engine, Exploit Mitigation, CFI |
| 2 | Services | Isolation, Zero-Copy IPC, Checkpoint/Restore, Replay, eBPF |
| 1 | Core | Capability Model, Service Registry, Process Manager, ASM Crypto |

## Naming Convention

This project follows a strict naming convention for all C++ code:

- **Member variables**: `m_` prefix + type + Name (e.g. `m_iCount`, `m_szName`, `m_vItems`)
- **Local variables**: `l` prefix + type + Name (e.g. `liResult`, `lszMessage`)
- **Arguments**: `a` prefix + type + Name (e.g. `aiCount`, `aSzPath`)
- **Type prefixes**: `i`=int, `f`=float, `d`=double, `c`=char, `sz`=string, `b`=bool, `v`=vector, `p`=pointer, `u`=unsigned, `e`=enum, `arr`=array

## License

TBD
