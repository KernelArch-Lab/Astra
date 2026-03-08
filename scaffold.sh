#!/bin/bash
# ============================================================================
# Astra Runtime - Full Project Structure Generator
# First commit: skeleton + main infrastructure file
# Target: Linux only, C++23 / x86-64 ASM
# ============================================================================

set -e

ROOT="$(cd "$(dirname "$0")" && pwd)"

echo "[*] Scaffolding Astra Runtime project at: $ROOT"
echo ""

# --------------------------------------------------------------------------
# Top-level build and config
# --------------------------------------------------------------------------
mkdir -p "$ROOT/cmake/modules"
mkdir -p "$ROOT/cmake/presets"

# --------------------------------------------------------------------------
# Scripts for CI, setup, and utilities
# --------------------------------------------------------------------------
mkdir -p "$ROOT/scripts/ci"
mkdir -p "$ROOT/scripts/setup"
mkdir -p "$ROOT/scripts/security"
mkdir -p "$ROOT/scripts/benchmark"

# --------------------------------------------------------------------------
# Third-party dependencies (pinned to commit hashes)
# --------------------------------------------------------------------------
mkdir -p "$ROOT/third_party"

# --------------------------------------------------------------------------
# Documentation tree
# --------------------------------------------------------------------------
mkdir -p "$ROOT/docs/architecture"
mkdir -p "$ROOT/docs/security/pentest"
mkdir -p "$ROOT/docs/security/threat_models"
mkdir -p "$ROOT/docs/security/advisories"
mkdir -p "$ROOT/docs/api"
mkdir -p "$ROOT/docs/research/papers"
mkdir -p "$ROOT/docs/onboarding"
mkdir -p "$ROOT/docs/module_specs"

# --------------------------------------------------------------------------
# Tools - astractl CLI
# --------------------------------------------------------------------------
mkdir -p "$ROOT/tools/astractl/src"
mkdir -p "$ROOT/tools/astractl/include/astractl"

# --------------------------------------------------------------------------
# Examples and demo applications
# --------------------------------------------------------------------------
mkdir -p "$ROOT/examples/basic_sandbox"
mkdir -p "$ROOT/examples/ipc_demo"
mkdir -p "$ROOT/examples/checkpoint_demo"

# --------------------------------------------------------------------------
# Benchmarks (separate from tests)
# --------------------------------------------------------------------------
mkdir -p "$ROOT/benchmarks/core"
mkdir -p "$ROOT/benchmarks/ipc"
mkdir -p "$ROOT/benchmarks/allocator"
mkdir -p "$ROOT/benchmarks/crypto"

# --------------------------------------------------------------------------
# Formal verification artefacts
# --------------------------------------------------------------------------
mkdir -p "$ROOT/formal/tlaplus"
mkdir -p "$ROOT/formal/coq"
mkdir -p "$ROOT/formal/cbmc"

# --------------------------------------------------------------------------
# AI training pipeline (Python, separate from C++ build)
# --------------------------------------------------------------------------
mkdir -p "$ROOT/ai_pipeline/training"
mkdir -p "$ROOT/ai_pipeline/models"
mkdir -p "$ROOT/ai_pipeline/datasets"

# --------------------------------------------------------------------------
# Public headers: include/astra/<module>/
# One directory per module. This is what consumers include.
# --------------------------------------------------------------------------
MODULE_HEADERS=(
    "core"              # M-01  Core Runtime
    "isolation"         # M-02  Isolation Layer (Isol8)
    "ipc"               # M-03  Zero-Copy IPC Engine
    "checkpoint"        # M-04  Checkpoint / Restore
    "replay"            # M-05  Deterministic Replay
    "allocator"         # M-06  Adaptive Memory Allocator
    "jobengine"         # M-07  Job Engine
    "ai"                # M-08  AI Intelligence Subsystem
    "ebpf"              # M-09  eBPF Observability
    "wasm"              # M-10  WebAssembly Sandbox
    "aql"               # M-11  Astra Query Language
    "verify"            # M-12  Formal Verification Layer
    "net"               # M-13  Userspace Network Stack
    "vfs"               # M-14  Virtual Filesystem Layer
    "consensus"         # M-15  Distributed Consensus (Raft)
    "hal"               # M-16  Hardware Abstraction Layer
    "profiler"          # M-17  Runtime Profiler
    "crypto"            # M-18  Cryptographic Capability Module
    "vtime"             # M-19  Virtual Time Subsystem
    "loader"            # M-20  Dynamic Module Loader
    "asm_core"          # M-21  Hardened Crypto & Memory Core (ASM)
)

for mod in "${MODULE_HEADERS[@]}"; do
    mkdir -p "$ROOT/include/astra/$mod"
done

# Shared / common headers used across modules
mkdir -p "$ROOT/include/astra/common"
mkdir -p "$ROOT/include/astra/platform"

# --------------------------------------------------------------------------
# Source directories: src/<module>/
# Implementation files live here. Not exposed publicly.
# --------------------------------------------------------------------------
MODULE_SOURCES=(
    "core"
    "isolation"
    "ipc"
    "checkpoint"
    "replay"
    "allocator"
    "jobengine"
    "ai"
    "ebpf"
    "wasm"
    "aql"
    "verify"
    "net"
    "vfs"
    "consensus"
    "hal"
    "profiler"
    "crypto"
    "vtime"
    "loader"
    "asm_core"
)

for mod in "${MODULE_SOURCES[@]}"; do
    mkdir -p "$ROOT/src/$mod"
done

# M-21 Assembly sources get their own subdirectory
mkdir -p "$ROOT/src/asm_core/asm"

# --------------------------------------------------------------------------
# Test directories: tests/<module>/
# Mirrors source tree. Each module gets unit + integration + fuzz dirs.
# --------------------------------------------------------------------------
for mod in "${MODULE_SOURCES[@]}"; do
    mkdir -p "$ROOT/tests/$mod/unit"
    mkdir -p "$ROOT/tests/$mod/integration"
    mkdir -p "$ROOT/tests/$mod/fuzz"
done

# Shared test utilities
mkdir -p "$ROOT/tests/common"
mkdir -p "$ROOT/tests/fixtures"

# Security-specific test infrastructure
mkdir -p "$ROOT/tests/security/pentest"
mkdir -p "$ROOT/tests/security/timing"
mkdir -p "$ROOT/tests/security/sanitizer_configs"

# --------------------------------------------------------------------------
# Summary
# --------------------------------------------------------------------------
echo ""
echo "[+] Directory structure created."
echo ""
echo "    Module count  : ${#MODULE_SOURCES[@]}"
echo "    Header root   : include/astra/"
echo "    Source root    : src/"
echo "    Test root     : tests/"
echo "    ASM sources   : src/asm_core/asm/"
echo ""
echo "    Run 'find $ROOT -type d | wc -l' to verify directory count."
echo ""
echo "[*] Done."
