#!/usr/bin/env bash
# ============================================================================
# Astra Runtime - Paper 1 (USENIX ATC 2027) reproducible benchmark sweep
# scripts/run_paper1_sweep.sh
#
# Track B Sprint 7 (+ AE hardening). Runs every baseline harness in the
# same TSC domain, same warm-up policy, same payload sweep. Each benchmark
# is executed REPS times end-to-end (fresh process per run, paper
# methodology: five repetitions, median-of-runs reported, >5% CoV
# flagged); scripts/paper1_merge_reps.py folds the repetitions into the
# canonical CSVs the plotters read and writes a CoV stability report.
#
# The host environment (kernel, governor, isolation, SMT, compiler,
# commit) is captured next to the CSVs — numbers without provenance are
# not paper numbers.
#
# Usage
# -----
#   ./scripts/run_paper1_sweep.sh                       # 5 repetitions
#   ./scripts/run_paper1_sweep.sh --reps 3              # custom
#   ./scripts/run_paper1_sweep.sh --quick               # 1 rep (smoke test)
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
REPS=5
# Per-repetition ceiling. Generous — a healthy rep is well under a minute
# — but bounded, so a wedged benchmark fails loudly instead of hanging.
BENCH_TIMEOUT="${BENCH_TIMEOUT:-300s}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --build-dir) BUILD_DIR="$2"; shift 2;;
        --out)       OUT_FILE="$2"; shift 2;;
        --reps)      REPS="$2"; shift 2;;
        --quick)     REPS=1; shift;;
        --perf)      PERF="perf stat -e cache-misses,context-switches"; shift;;
        -h|--help)
            sed -n '2,33p' "$0"
            exit 0;;
        *) echo "unknown arg: $1" >&2; exit 1;;
    esac
done

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

ART_DIR="$(dirname "$OUT_FILE")"
mkdir -p "$ART_DIR"

# Environment guard. Lives HERE rather than in compile-astra.sh because both
# entry points (compile-astra.sh paper1 and a direct sweep) come through this
# script, and a guard that only one path runs is a guard that does not exist.
# Aborts on a host that would produce unpublishable numbers — chiefly
# benchmark cores split across NUMA nodes, which routes the IPC ring over the
# socket interconnect and inflates every latency with no visible error.
# ASTRA_ALLOW_BAD_ENV=1 overrides.
if [[ -x "$ROOT/scripts/paper1_env_guard.py" ]]; then
    if ! python3 "$ROOT/scripts/paper1_env_guard.py" \
            --json "$ART_DIR/environment_guard.json"; then
        if [[ "${ASTRA_ALLOW_BAD_ENV:-0}" == "1" ]]; then
            echo "WARNING: environment guard failed but ASTRA_ALLOW_BAD_ENV=1 — continuing." >&2
        else
            echo "ERROR: environment guard refused this host. Fix the failures above," >&2
            echo "       or set ASTRA_ALLOW_BAD_ENV=1 to run anyway." >&2
            exit 3
        fi
    fi
    echo
fi
mkdir -p "$ART_DIR"
MERGE="python3 scripts/paper1_merge_reps.py"
COV_REPORT="$ART_DIR/paper1_cov_report.txt"
: > "$COV_REPORT"

# --- 0. Environment capture + tuning warnings --------------------------------
ENV_FILE="$ART_DIR/environment.txt"
{
    echo "# Captured by run_paper1_sweep.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "git_commit:   $(git rev-parse HEAD 2>/dev/null || echo unknown)"
    echo "git_dirty:    $(git status --porcelain 2>/dev/null | wc -l | tr -d ' ') modified files"
    echo "kernel:       $(uname -sr)"
    echo "cmdline:      $(cat /proc/cmdline 2>/dev/null || echo n/a)"
    echo "cpu_model:    $(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2- || echo n/a)"
    echo "governor:     $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo n/a)"
    echo "smt:          $(cat /sys/devices/system/cpu/smt/control 2>/dev/null || echo n/a)"
    echo "isolcpus:     $(grep -o 'isolcpus=[^ ]*' /proc/cmdline 2>/dev/null || echo none)"
    echo "compiler:     $(c++ --version 2>/dev/null | head -1 || echo n/a)"
    echo "cmake:        $(cmake --version 2>/dev/null | head -1 || echo n/a)"
    echo "reps:         $REPS"
} > "$ENV_FILE"
echo "==> Environment captured to $ENV_FILE"

GOV="$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo unknown)"
if [[ "$GOV" != "performance" ]]; then
    echo "WARNING: cpufreq governor is '$GOV', not 'performance'." >&2
    echo "         sudo cpupower frequency-set -g performance" >&2
fi
SMT="$(cat /sys/devices/system/cpu/smt/control 2>/dev/null || echo unknown)"
if [[ "$SMT" == "on" ]]; then
    echo "WARNING: SMT is enabled — paper numbers are taken with SMT off." >&2
    echo "         sudo grubby --update-kernel=ALL --args=\"nosmt\" && reboot" >&2
fi
if ! grep -q isolcpus /proc/cmdline 2>/dev/null; then
    echo "WARNING: no isolcpus= on the kernel cmdline — expect noisier tails." >&2
    echo "         sudo grubby --update-kernel=ALL \\" >&2
    echo "           --args=\"nosmt isolcpus=2,3 nohz_full=2,3 rcu_nocbs=2,3\"" >&2
fi

# --- 1. Build all baselines -------------------------------------------------
echo "==> Building paper1_baselines target in $BUILD_DIR"
if [[ ! -d "$BUILD_DIR" ]]; then
    cmake -B "$BUILD_DIR" -S . -DCMAKE_BUILD_TYPE=Release \
                                -DASTRA_ENABLE_TESTS=ON
fi
cmake --build "$BUILD_DIR" --target paper1_baselines -j

# --- 2. Repetition runner ----------------------------------------------------
# run_one <binary> <out-file> <k> <total>: one repetition.
# Split out of run_reps so the required baselines can be interleaved
# repetition-major (see section 3) while aeron/erpc stay blocked.
run_one () {
    local name="$1"
    local outFile="$2"
    local k="$3"
    local total="$4"
    local bin="$BUILD_DIR/tests/bench/$name"
    if [[ ! -x "$bin" ]]; then
        echo "  SKIP $name (binary missing)"
        return 2
    fi
    echo "  RUN  $name (rep $k/$total)"
    # Hard timeout per repetition. A benchmark that wedges (SQPOLL's
    # idle/wakeup handshake managed this on a core-starved host) must
    # surface as a failure, not stall the sweep indefinitely.
    # Capture the status via `|| rc=$?`, not `if ! cmd`. With `if !`,
    # $? inside the branch is the NEGATION's result (0), so every
    # failure reported a useless "exit 0".
    local rc=0
    timeout --kill-after=10s "${BENCH_TIMEOUT}" \
        $PERF "$bin" > "$outFile" 2>/dev/null || rc=$?
    if [[ $rc -ne 0 ]]; then
        if [[ $rc -eq 124 || $rc -eq 137 ]]; then
            echo "  TIMEOUT $name rep $k (>${BENCH_TIMEOUT}) — killed" >&2
        else
            echo "  FAIL $name rep $k (exit $rc)" >&2
        fi
        return 1
    fi
    return 0
}

# run_reps <binary> <out-base>: runs REPS times into <out-base>.repK.csv.
# Benchmark-major. Still used where a repetition cannot be interleaved with
# anything else — aeron needs its media driver held up across its own reps,
# and the Sprint 8 metrics are not differenced against each other.
# Returns 1 if any required rep fails.
run_reps () {
    local name="$1"
    local outBase="$2"
    local bin="$BUILD_DIR/tests/bench/$name"
    if [[ ! -x "$bin" ]]; then
        echo "  SKIP $name (binary missing)"
        return 2
    fi
    local k
    for k in $(seq 1 "$REPS"); do
        run_one "$name" "${outBase}.rep${k}.csv" "$k" "$REPS" || return $?
    done
    return 0
}

# --- 3. Required baselines (RTT figure) --------------------------------------
echo "==> Running required baselines ($REPS reps each)"
REQ=(bench_baseline_pipe
     bench_baseline_socketpair
     bench_baseline_io_uring
     bench_baseline_astra
     bench_baseline_astra_gated)

REQ_CSVS=()
for b in "${REQ[@]}"; do
    for k in $(seq 1 "$REPS"); do REQ_CSVS+=("$ART_DIR/_${b}.rep${k}.csv"); done
done

# INTERLEAVED, repetition-major. This matters for correctness, not tidiness.
#
# Benchmark-major ordering ran all five astra repetitions to completion
# before the first astra_gated repetition started, so raw and gated were
# measured in two separate time blocks. Any drift across the sweep then
# lands directly in their difference — and the gate cost IS that difference.
# On 2026-08-16 raw drifted -8.2% while gated held roughly flat, so the
# reported gate cost (median gated - median raw)/2 = 7.6 ns took its raw
# term from repetition 1/3 and its gated term from repetition 5. The median
# of the per-repetition differences was 10.0 ns: the paper understated its
# own gate cost by 24% purely from ordering.
#
# Repetition-major puts rep k of every transport within seconds of rep k of
# every other, so drift is common-mode and cancels in the difference.
for k in $(seq 1 "$REPS"); do
    for b in "${REQ[@]}"; do
        run_one "$b" "$ART_DIR/_${b}.rep${k}.csv" "$k" "$REPS" || true
    done
done

# --- Aeron media driver ------------------------------------------------------
# Aeron's C++ client is useless without a running media driver: it talks to
# aeronmd through the CnC file under /dev/shm. Start one for the duration of
# the Aeron reps and take it down afterwards. AERON_DIR is exported by
# compile-astra.sh's paper1 pipeline; a manual sweep can export it too.
# CAREFUL: AERON_DIR is Aeron's OWN environment variable — both the media
# driver and the client read it to locate their shared-memory directory
# (default /dev/shm/aeron-$USER). If a caller exported it pointing at the
# Aeron *source tree* (as our build once did), the driver writes its CnC
# file there and nothing lines up. Use ASTRA_AERON_HOME for the build
# location and clear AERON_DIR so Aeron uses its own default.
ASTRA_AERON_HOME="${ASTRA_AERON_HOME:-${ROOT}/third_party/aeron}"
unset AERON_DIR

AERONMD_PID=""
start_aeronmd () {
    local md=""
    for cand in "$ASTRA_AERON_HOME/cppbuild/Release/binaries/aeronmd" \
                "$ASTRA_AERON_HOME/cppbuild/Release/aeronmd" \
                "$(command -v aeronmd 2>/dev/null || true)"; do
        [[ -n "$cand" && -x "$cand" ]] && { md="$cand"; break; }
    done
    if [[ -z "$md" ]]; then
        echo "  NOTE aeronmd not found — Aeron baseline will emit SKIPPED" >&2
        return 1
    fi
    echo "  START aeronmd ($md)"
    "$md" >"$ART_DIR/_aeronmd.log" 2>&1 &
    AERONMD_PID=$!
    # Wait (max 30s) for the driver to publish its CnC file. Aeron's
    # default directory is /dev/shm/aeron-$USER.
    local waited=0
    while [[ $waited -lt 300 ]]; do
        compgen -G "/dev/shm/aeron-*/cnc.dat" >/dev/null 2>&1 && {
            echo "  OK    CnC file up after $((waited / 10))s"; return 0; }
        kill -0 "$AERONMD_PID" 2>/dev/null || {
            echo "  FAIL aeronmd died. Last lines of its log:" >&2
            tail -5 "$ART_DIR/_aeronmd.log" >&2 || true
            AERONMD_PID=""; return 1; }
        sleep 0.1; waited=$((waited + 1))
    done
    echo "  WARN aeronmd alive but no CnC file after 30s. Log tail:" >&2
    tail -5 "$ART_DIR/_aeronmd.log" >&2 || true
    return 0
}
stop_aeronmd () {
    [[ -n "$AERONMD_PID" ]] || return 0
    echo "  STOP  aeronmd"
    kill "$AERONMD_PID" 2>/dev/null || true
    wait "$AERONMD_PID" 2>/dev/null || true
    AERONMD_PID=""
}
trap stop_aeronmd EXIT

# Optional — present if dep installed; otherwise skipped.
start_aeronmd || true
for b in bench_baseline_aeron bench_baseline_erpc; do
    if run_reps "$b" "$ART_DIR/_${b}"; then
        for k in $(seq 1 "$REPS"); do REQ_CSVS+=("$ART_DIR/_${b}.rep${k}.csv"); done
    fi
    [[ "$b" == "bench_baseline_aeron" ]] && stop_aeronmd
done

# Median-merge every transport's reps into the canonical figure-1 CSV.
$MERGE --mode median --key transport,payload_bytes \
       --out "$OUT_FILE" --cov-report "$COV_REPORT" "${REQ_CSVS[@]}"

# --- 4. Sprint 8 extended metrics --------------------------------------------
echo "==> Running Sprint 8 metrics ($REPS reps each)"

merge_metric () {
    local name="$1" out="$2" mode="$3" key="$4"
    local reps=() k
    if ! run_reps "$name" "$ART_DIR/_${name}"; then
        return 0    # optional path: binary missing or failed — plotters self-skip
    fi
    for k in $(seq 1 "$REPS"); do reps+=("$ART_DIR/_${name}.rep${k}.csv"); done
    if [[ "$mode" == "median" ]]; then
        $MERGE --mode median --key "$key" \
               --out "$out" --cov-report "$COV_REPORT" "${reps[@]}"
    else
        $MERGE --mode concat --out "$out" "${reps[@]}"
    fi
}

merge_metric bench_throughput         "$ART_DIR/paper1_throughput.csv"      median transport,payload_bytes
merge_metric bench_throughput_mpsc    "$ART_DIR/paper1_throughput_mpsc.csv" median transport,payload_bytes,producers,gate_state
merge_metric bench_revocation_latency "$ART_DIR/paper1_revocation.csv"      concat -
merge_metric bench_perfcounters       "$ART_DIR/paper1_perfcounters.csv"    median metric,pool_active
merge_metric bench_pool_scaling       "$ART_DIR/paper1_pool_scaling.csv"    median metric,pool_active
# The instrument's own cost. Every latency above is sampled through an
# rdtscp+lfence bracket; this measures an empty bracket so the additive
# constant is published rather than left implicit. It cancels in the gate
# cost (a difference) but inflates every absolute figure, most for the
# fastest transports.
merge_metric bench_timer_floor        "$ART_DIR/paper1_timer_floor.csv"     median metric

# --- 5. Summary -------------------------------------------------------------
echo
echo "==> Sweep complete ($REPS repetitions, median-merged)"
echo "    Environment:           $ENV_FILE"
echo "    CoV stability report:  $COV_REPORT"
echo "    Figure 1 (latency):    $OUT_FILE  ($(wc -l < "$OUT_FILE") rows)"
echo "    Throughput:            $ART_DIR/paper1_throughput.csv"
echo "    MPSC scaling:          $ART_DIR/paper1_throughput_mpsc.csv"
echo "    Revocation latency:    $ART_DIR/paper1_revocation.csv"
echo "    Perf counters:         $ART_DIR/paper1_perfcounters.csv"
echo "    Pool-size scaling:     $ART_DIR/paper1_pool_scaling.csv"
echo
echo "    Per-repetition raw CSVs kept as $ART_DIR/_<bench>.repK.csv"
echo "    Figure 1 plot:    python3 scripts/plot_paper1_figure.py $OUT_FILE"
echo "    Figure 2 plot:    python3 scripts/plot_paper1_figure_2.py $ART_DIR/paper1_pool_scaling.csv"
echo "    Quick read:       column -t -s, $OUT_FILE | sort -k1,1 -k2,2n"

# --- 6. Run quality report --------------------------------------------------
# The summary above says what was measured. This says whether to trust it,
# and writes run_summary.json for paper1_compare_runs.py to diff against a
# later run. Never fails the sweep: the data is already on disk and worth
# keeping even if the report itself has a problem.
if [[ -x "$ROOT/scripts/paper1_run_report.py" ]]; then
    echo
    python3 "$ROOT/scripts/paper1_run_report.py" \
        --artefact "$ART_DIR" --json "$ART_DIR/run_summary.json" || true
fi
