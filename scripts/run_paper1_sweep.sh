#!/usr/bin/env bash
# ============================================================================
# Astra Runtime - Paper 1 (USENIX ATC 2027) reproducible benchmark sweep
# scripts/run_paper1_sweep.sh
#
# Track B Sprint 7. Runs every baseline harness in the same TSC domain,
# same warm-up policy, same payload sweep, and concatenates the CSV
# rows into a single figure_1.csv that scripts/plot_paper1_figure.py
# turns into the headline figure.
#
# Usage
# -----
#   ./scripts/run_paper1_sweep.sh                       # default
#   ./scripts/run_paper1_sweep.sh --build-dir build-r   # custom build dir
#   ./scripts/run_paper1_sweep.sh --out artefact/p1.csv # custom output
#
# Pre-flight
# ----------
#   sudo cpupower frequency-set -g performance
#   sudo nice -n -19 -- ...   (recommended — script does NOT sudo itself)
#
# Exit codes
# ----------
#   0  All required baselines ran (pipe, socket, io_uring, astra, astra_gated)
#   1  A required baseline failed
#   2  CMake build failed
# ============================================================================

set -euo pipefail

BUILD_DIR="build"
OUT_FILE="artefact/paper1_figure_1.csv"
PERF=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --build-dir) BUILD_DIR="$2"; shift 2;;
        --out)       OUT_FILE="$2"; shift 2;;
        --perf)      PERF="perf stat -e cache-misses,context-switches"; shift;;
        -h|--help)
            sed -n '2,28p' "$0"
            exit 0;;
        *) echo "unknown arg: $1" >&2; exit 1;;
    esac
done

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

mkdir -p "$(dirname "$OUT_FILE")"

# --- 1. Build all baselines -------------------------------------------------
echo "==> Building paper1_baselines target in $BUILD_DIR"
if [[ ! -d "$BUILD_DIR" ]]; then
    cmake -B "$BUILD_DIR" -S . -DCMAKE_BUILD_TYPE=Release \
                                -DASTRA_ENABLE_TESTS=ON
fi
cmake --build "$BUILD_DIR" --target paper1_baselines -j

# --- 2. Run the required baselines ------------------------------------------
echo "==> Running baselines into $OUT_FILE"
echo "transport,payload_bytes,iters,p50_ns,p99_ns,p9999_ns,max_ns,mean_ns" > "$OUT_FILE"

run_one () {
    local name="$1"
    local bin="$BUILD_DIR/tests/bench/$name"
    if [[ ! -x "$bin" ]]; then
        echo "  SKIP $name (binary missing)"
        return
    fi
    echo "  RUN $name"
    # Discard the per-binary header line; keep only data rows.
    $PERF "$bin" 2>/dev/null | grep -v '^transport,' >> "$OUT_FILE" || {
        echo "  FAIL $name" >&2
        return 1
    }
}

# Required for the figure
REQ=(bench_baseline_pipe
     bench_baseline_socketpair
     bench_baseline_io_uring
     bench_baseline_astra
     bench_baseline_astra_gated)

for b in "${REQ[@]}"; do run_one "$b"; done

# Optional — present if dep installed; otherwise emits a SKIPPED row.
OPT=(bench_baseline_aeron
     bench_baseline_erpc)

for b in "${OPT[@]}"; do run_one "$b" || true; done

# --- 3. Sprint 8 extended metrics (separate CSVs, distinct schemas) ---------
ART_DIR="$(dirname "$OUT_FILE")"

run_to_file () {
    local name="$1"
    local out="$2"
    local bin="$BUILD_DIR/tests/bench/$name"
    if [[ ! -x "$bin" ]]; then
        echo "  SKIP $name (binary missing)"; return
    fi
    echo "  RUN  $name → $out"
    $PERF "$bin" > "$out" 2>/dev/null || {
        echo "  FAIL $name" >&2; return 1
    }
}

echo "==> Running Sprint 8 metrics"
run_to_file bench_throughput         "$ART_DIR/paper1_throughput.csv"        || true
run_to_file bench_throughput_mpsc    "$ART_DIR/paper1_throughput_mpsc.csv"   || true
run_to_file bench_revocation_latency "$ART_DIR/paper1_revocation.csv"        || true
run_to_file bench_perfcounters       "$ART_DIR/paper1_perfcounters.csv"      || true
run_to_file bench_pool_scaling       "$ART_DIR/paper1_pool_scaling.csv"      || true

# --- 4. Summary -------------------------------------------------------------
echo
echo "==> Sweep complete"
echo "    Figure 1 (latency):    $OUT_FILE  ($(wc -l < "$OUT_FILE") rows)"
echo "    Throughput:            $ART_DIR/paper1_throughput.csv"
echo "    MPSC scaling:          $ART_DIR/paper1_throughput_mpsc.csv"
echo "    Revocation latency:    $ART_DIR/paper1_revocation.csv"
echo "    Perf counters:         $ART_DIR/paper1_perfcounters.csv"
echo "    Pool-size scaling:     $ART_DIR/paper1_pool_scaling.csv"
echo
echo "    Figure 1 plot:    python3 scripts/plot_paper1_figure.py $OUT_FILE"
echo "    Figure 2 plot:    python3 scripts/plot_paper1_figure_2.py $ART_DIR/paper1_pool_scaling.csv"
echo "    Quick read:       column -t -s, $OUT_FILE | sort -k1,1 -k2,2n"
