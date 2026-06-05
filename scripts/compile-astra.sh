#!/usr/bin/env bash
# ============================================================================
# Astra Runtime - single-entry build driver (Fedora-targeted)
#
# Everything that needs to happen on a clean Fedora x86_64 host between
# `git pull` and a built+tested+verified runtime + paper PDF lives here.
# Sub-commands are composable; default (no args) preserves the legacy
# behaviour (configure + build + ctest).
#
# Usage:
#   ./scripts/compile-astra.sh                 # configure + build + test (default)
#   ./scripts/compile-astra.sh -R Sprint5      # forward arg to ctest
#
#   ./scripts/compile-astra.sh deps            # dnf install prerequisites
#   ./scripts/compile-astra.sh check           # pre-flight checks
#   ./scripts/compile-astra.sh sysctl          # enable userns + perf sysctls
#   ./scripts/compile-astra.sh build           # explicit configure+build+test
#   ./scripts/compile-astra.sh cbmc            # run CBMC monotonicity proof
#   ./scripts/compile-astra.sh sweep           # run Paper-1 bench sweep
#   ./scripts/compile-astra.sh paper           # build Paper-1 PDF
#   ./scripts/compile-astra.sh clean           # rm -rf build/ artefact/
#
#   ./scripts/compile-astra.sh all             # deps + check + sysctl + build
#                                              #   + cbmc + sweep + paper
#
# Build-type / parallelism overrides (env vars):
#   ASTRA_BUILD_TYPE=Release  ./scripts/compile-astra.sh
#   ASTRA_BUILD_TYPE=Sanitize ./scripts/compile-astra.sh    # ASAN+UBSAN
#   ASTRA_BUILD_TYPE=Tsan     ./scripts/compile-astra.sh    # ThreadSanitizer
#   ASTRA_JOBS=8              ./scripts/compile-astra.sh
#
# Shorthand flags:
#   --release | --sanitize | --tsan          # set ASTRA_BUILD_TYPE
#   --skip-tests                             # build only, no ctest
#   --no-color                               # disable terminal colours
#
# Exit codes:
#   0  success
#   1  build / test failure
#   2  missing prerequisite (dep, tool, kernel feature)
#   3  unsupported host (non-Linux, non-x86_64)
#   4  invalid command-line argument
# ============================================================================
set -euo pipefail

# ---- locations -------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$REPO_ROOT/build"
ARTEFACT_DIR="$REPO_ROOT/artefact"
PAPER_DIR="$REPO_ROOT/papers/paper1"
CBMC_DIR="$REPO_ROOT/formal/cbmc"

# ---- knobs -----------------------------------------------------------------
BUILD_TYPE="${ASTRA_BUILD_TYPE:-Debug}"
JOBS="${ASTRA_JOBS:-$(nproc 2>/dev/null || echo 4)}"
SKIP_TESTS=0
COLOR=1

# ---- colour helpers --------------------------------------------------------
if [[ -t 1 ]] && [[ "${TERM:-}" != "dumb" ]]; then COLOR=1; else COLOR=0; fi

_clr() { [[ $COLOR -eq 1 ]] && printf '\033[%sm' "$1" || true; }
ok()   { printf '%s==>%s %s\n' "$(_clr '1;32')" "$(_clr 0)" "$*"; }
info() { printf '%s==>%s %s\n' "$(_clr '1;34')" "$(_clr 0)" "$*"; }
warn() { printf '%s==>%s %s\n' "$(_clr '1;33')" "$(_clr 0)" "$*" >&2; }
err()  { printf '%s==>%s %s\n' "$(_clr '1;31')" "$(_clr 0)" "$*" >&2; }

# ---- preconditions ---------------------------------------------------------
check_host() {
    local kernel arch
    kernel="$(uname -s)"
    arch="$(uname -m)"
    if [[ "$kernel" != "Linux" ]]; then
        err "Astra targets Linux only. Detected: $kernel"
        exit 3
    fi
    if [[ "$arch" != "x86_64" ]]; then
        err "Astra targets x86_64 only. Detected: $arch"
        exit 3
    fi
}

have() { command -v "$1" >/dev/null 2>&1; }

require_cmd() {
    local cmd="$1" pkg="${2:-$1}"
    if ! have "$cmd"; then
        err "Missing required tool: $cmd"
        err "  Install on Fedora:  sudo dnf install $pkg"
        err "  Or run:             $0 deps"
        return 2
    fi
}

# ===========================================================================
# Sub-command: deps
# ===========================================================================
cmd_deps() {
    info "Installing Fedora prerequisites (dnf)"
    if ! have dnf; then
        err "dnf not found; this command is Fedora-only."
        err "On Ubuntu use: sudo apt install g++-13 cmake nasm libbpf-dev libelf-dev clang liburing-dev cbmc python3-matplotlib texlive-latex-recommended"
        exit 2
    fi
    sudo dnf install -y \
        gcc-c++ cmake ninja-build nasm \
        libbpf-devel elfutils-libelf-devel clang clang-tools-extra \
        liburing-devel \
        perf cbmc \
        gdb strace \
        python3-matplotlib \
        texlive-scheme-medium texlive-collection-latexrecommended \
        git
    ok "Prerequisites installed."
}

# ===========================================================================
# Sub-command: check  (pre-flight)
# ===========================================================================
cmd_check() {
    check_host
    info "Pre-flight checks"

    local fail=0
    for tuple in \
        "g++:gcc-c++" "cmake:cmake" "nasm:nasm" "clang:clang" \
        "python3:python3" "git:git" "make:make"
    do
        local cmd="${tuple%%:*}" pkg="${tuple##*:}"
        if have "$cmd"; then
            printf '  %sOK%s    %s\n' "$(_clr '1;32')" "$(_clr 0)" "$cmd"
        else
            printf '  %sMISS%s  %s    (sudo dnf install %s)\n' \
                "$(_clr '1;31')" "$(_clr 0)" "$cmd" "$pkg"
            fail=1
        fi
    done

    # GCC ≥ 13 for C++23
    if have g++; then
        local gccmaj
        gccmaj="$(g++ -dumpversion | cut -d. -f1)"
        if (( gccmaj < 13 )); then
            printf '  %sMISS%s  g++ %s — need 13+\n' "$(_clr '1;31')" "$(_clr 0)" "$gccmaj"
            fail=1
        fi
    fi

    # cmake ≥ 3.28
    if have cmake; then
        local cmv
        cmv="$(cmake --version | head -1 | awk '{print $3}')"
        if [[ "$(printf '3.28\n%s' "$cmv" | sort -V | head -1)" != "3.28" ]]; then
            printf '  %sMISS%s  cmake %s — need 3.28+\n' "$(_clr '1;31')" "$(_clr 0)" "$cmv"
            fail=1
        fi
    fi

    # Headers libbpf-devel + elfutils-libelf-devel
    for h in /usr/include/bpf/libbpf.h /usr/include/libelf.h; do
        if [[ -f "$h" ]]; then
            printf '  %sOK%s    %s\n' "$(_clr '1;32')" "$(_clr 0)" "$h"
        else
            printf '  %sMISS%s  %s    (sudo dnf install libbpf-devel elfutils-libelf-devel)\n' \
                "$(_clr '1;31')" "$(_clr 0)" "$h"
            fail=1
        fi
    done

    # Sysctls (warn-only — sysctl subcommand fixes them).
    # Modern Fedora kernels (~5.18+) removed kernel.unprivileged_userns_clone
    # because user namespaces are now always allowed. Treat a missing key
    # as "kernel grants by default" → OK.
    if [[ ! -e /proc/sys/kernel/unprivileged_userns_clone ]]; then
        printf '  %sOK%s    kernel.unprivileged_userns_clone (not exposed; always-allowed on this kernel)\n' \
            "$(_clr '1;32')" "$(_clr 0)"
    else
        local userns
        userns="$(sysctl -n kernel.unprivileged_userns_clone 2>/dev/null || echo 1)"
        if [[ "$userns" -eq 0 ]]; then
            printf '  %sWARN%s  kernel.unprivileged_userns_clone=0 — M-02 tests will need sudo\n' \
                "$(_clr '1;33')" "$(_clr 0)"
            printf '         fix:  %s sysctl\n' "$0"
        else
            printf '  %sOK%s    kernel.unprivileged_userns_clone=%s\n' \
                "$(_clr '1;32')" "$(_clr 0)" "$userns"
        fi
    fi

    local paranoid
    paranoid="$(sysctl -n kernel.perf_event_paranoid 2>/dev/null || echo 4)"
    if (( paranoid > 1 )); then
        printf '  %sWARN%s  kernel.perf_event_paranoid=%s — perfcounter bench will self-skip\n' \
            "$(_clr '1;33')" "$(_clr 0)" "$paranoid"
        printf '         fix:  %s sysctl\n' "$0"
    else
        printf '  %sOK%s    kernel.perf_event_paranoid=%s\n' \
            "$(_clr '1;32')" "$(_clr 0)" "$paranoid"
    fi

    # Optional Paper-1 tools
    for tuple in "cbmc:cbmc" "perf:perf" "pdflatex:texlive-scheme-medium" "python3-matplotlib:python3-matplotlib"
    do
        local cmd="${tuple%%:*}" pkg="${tuple##*:}"
        if have "$cmd" || python3 -c "import matplotlib" 2>/dev/null; then
            printf '  %sOK%s    %s (optional)\n' "$(_clr '1;32')" "$(_clr 0)" "$cmd"
        else
            printf '  %sopt%s   %s — not installed; needed by: cbmc/sweep/paper subcommand\n' \
                "$(_clr '1;33')" "$(_clr 0)" "$cmd"
        fi
    done

    # RDRAND (CapabilityManager fails closed without it)
    if grep -q rdrand /proc/cpuinfo 2>/dev/null; then
        printf '  %sOK%s    RDRAND supported (CPU)\n' "$(_clr '1;32')" "$(_clr 0)"
    else
        printf '  %sFAIL%s  RDRAND NOT supported by this CPU — runtime will refuse to mint tokens (audit C2)\n' \
            "$(_clr '1;31')" "$(_clr 0)"
        fail=1
    fi

    if (( fail )); then
        err "Pre-flight failed."
        return 2
    fi
    ok "Pre-flight OK."
}

# ===========================================================================
# Sub-command: sysctl
# ===========================================================================
cmd_sysctl() {
    info "Enabling kernel sysctls (sudo)"

    # Apply each sysctl independently — modern Fedora kernels no longer
    # expose kernel.unprivileged_userns_clone (the gate was removed in
    # ~5.18 and user namespaces are always available without it). Treat
    # missing keys as a soft skip rather than killing the script.
    local persist=()
    _apply_sysctl() {
        local key="$1" val="$2"
        if [[ ! -e "/proc/sys/${key//./\/}" ]]; then
            printf '  %sskip%s   %s — not exposed on this kernel (treated as default ok)\n' \
                "$(_clr '1;33')" "$(_clr 0)" "$key"
            return 0
        fi
        if sudo sysctl -w "$key=$val" >/dev/null; then
            printf '  %sOK%s     %s = %s\n' "$(_clr '1;32')" "$(_clr 0)" "$key" "$val"
            persist+=( "$key=$val" )
        else
            warn "Failed to set $key=$val"
            return 1
        fi
    }

    _apply_sysctl kernel.unprivileged_userns_clone 1 || true
    _apply_sysctl kernel.perf_event_paranoid 1 || true

    # Persist only the ones that actually applied.
    if [[ ${#persist[@]} -gt 0 ]]; then
        {
            echo "# Astra Runtime — kernel toggles required by M-02 isolation tests"
            echo "# and M-09 / paper-1 perfcounter benchmark."
            for kv in "${persist[@]}"; do echo "$kv"; done
        } | sudo tee /etc/sysctl.d/99-astra.conf >/dev/null
        ok "sysctls applied and persisted to /etc/sysctl.d/99-astra.conf"
    else
        warn "No applicable sysctls to persist on this kernel."
    fi
}

# ===========================================================================
# Sub-command: build  (configure + compile + ctest)  — also the default
# ===========================================================================
cmd_build() {
    check_host
    info "Configuring (build type: $BUILD_TYPE, jobs: $JOBS)"

    local cmake_args=( "-S" "$REPO_ROOT" "-B" "$BUILD_DIR" )
    case "$BUILD_TYPE" in
        Sanitize)
            cmake_args+=( "-DCMAKE_BUILD_TYPE=Debug" "-DASTRA_ENABLE_SANITIZERS=ON" )
            ;;
        Tsan)
            cmake_args+=( "-DCMAKE_BUILD_TYPE=Debug" "-DASTRA_ENABLE_TSAN=ON" )
            ;;
        *)
            cmake_args+=( "-DCMAKE_BUILD_TYPE=$BUILD_TYPE" )
            ;;
    esac
    cmake "${cmake_args[@]}"

    info "Building (-j$JOBS)"
    cmake --build "$BUILD_DIR" -j"$JOBS"

    if (( SKIP_TESTS )); then
        ok "Build succeeded (tests skipped)."
        return 0
    fi

    info "Running tests"
    if ! ctest --test-dir "$BUILD_DIR" --output-on-failure "$@"; then
        err "Tests failed."
        return 1
    fi
    ok "Build + tests passed."
}

# ===========================================================================
# Sub-command: cbmc  (formal verification of capability monotonicity)
# ===========================================================================
cmd_cbmc() {
    require_cmd cbmc cbmc || return 2
    info "Running CBMC monotonicity proof"
    if ! make -C "$CBMC_DIR" verify; then
        err "CBMC verification FAILED — capability monotonicity broken."
        return 1
    fi
    ok "CBMC proof PASSED (Paper-1 §5 citation intact)."
}

# ===========================================================================
# Sub-command: sweep  (Paper-1 benchmark sweep — produces artefact/*.csv)
# ===========================================================================
cmd_sweep() {
    check_host
    require_cmd python3 python3 || return 2

    if [[ ! -d "$BUILD_DIR" ]]; then
        info "build/ missing — running build first"
        cmd_build || return 1
    fi

    # Pre-flight if the script is around
    if [[ -x "$REPO_ROOT/scripts/check_paper1_env.sh" ]]; then
        info "Verifying Paper-1 environment"
        "$REPO_ROOT/scripts/check_paper1_env.sh" || warn "Some optional Paper-1 deps missing; sweep may emit SKIPPED rows."
    fi

    info "Running Paper-1 benchmark sweep (sudo recommended for perfcounters)"
    if [[ $EUID -ne 0 ]]; then
        warn "Not running as root — bench_perfcounters may self-skip if perf_event_paranoid > 1."
    fi
    "$REPO_ROOT/scripts/run_paper1_sweep.sh" --build-dir "$BUILD_DIR"

    if ls "$ARTEFACT_DIR"/paper1_*.csv >/dev/null 2>&1; then
        ok "Sweep complete. CSVs under $ARTEFACT_DIR/"
        ls -1 "$ARTEFACT_DIR" | sed 's/^/    /'
    else
        warn "Sweep finished but no CSVs found at $ARTEFACT_DIR/"
    fi
}

# ===========================================================================
# Sub-command: paper  (build the Paper-1 PDF — refresh figures if CSVs present)
# ===========================================================================
cmd_paper() {
    require_cmd pdflatex texlive-scheme-medium || return 2

    local refresh_flag=""
    if ls "$ARTEFACT_DIR"/paper1_*.csv >/dev/null 2>&1; then
        info "Found benchmark CSVs — running build.sh --refresh"
        refresh_flag="--refresh"
    else
        warn "No benchmark CSVs at $ARTEFACT_DIR/ — building PDF with red [placeholder] markers"
        warn "Run '$0 sweep' first to populate real numbers."
    fi

    if ! ( cd "$PAPER_DIR" && ./build.sh $refresh_flag ); then
        err "Paper PDF build FAILED."
        return 1
    fi
    ok "Paper PDF: $PAPER_DIR/main.pdf"
}

# ===========================================================================
# Sub-command: clean
# ===========================================================================
cmd_clean() {
    info "Removing build/ and artefact/"
    rm -rf "$BUILD_DIR" "$ARTEFACT_DIR"
    # Paper-1 artefacts that are gitignored
    rm -rf "$PAPER_DIR/numbers" "$PAPER_DIR"/figures/*.pdf \
           "$PAPER_DIR"/main.pdf "$PAPER_DIR"/main.aux \
           "$PAPER_DIR"/main.log "$PAPER_DIR"/main.bbl \
           "$PAPER_DIR"/main.blg "$PAPER_DIR"/main.out
    ok "Clean."
}

# ===========================================================================
# Sub-command: all  (full pipeline)
# ===========================================================================
cmd_all() {
    cmd_check       || exit $?
    cmd_sysctl      || exit $?
    cmd_build       || exit $?
    cmd_cbmc        || exit $?
    cmd_sweep       || exit $?
    cmd_paper       || exit $?
    ok "ALL phases complete."
}

# ===========================================================================
# Argument parser
# ===========================================================================
usage() {
    sed -n '2,43p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

# Flags first (must precede sub-command; sub-command swallows the rest)
SUBCMD=""
PASSTHRU=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --release)     BUILD_TYPE="Release"; shift ;;
        --sanitize)    BUILD_TYPE="Sanitize"; shift ;;
        --tsan)        BUILD_TYPE="Tsan"; shift ;;
        --skip-tests)  SKIP_TESTS=1; shift ;;
        --no-color)    COLOR=0; shift ;;
        -h|--help)     usage; exit 0 ;;
        deps|check|sysctl|build|cbmc|sweep|paper|clean|all)
                       SUBCMD="$1"; shift; PASSTHRU=( "$@" ); break ;;
        -R|-E|-L|-j)   # ctest-style args — treat as default (build) passthru
                       PASSTHRU=( "$@" ); break ;;
        *)             # anything else → forward to ctest
                       PASSTHRU=( "$@" ); break ;;
    esac
done

# No sub-command and no ctest filter → default is `build`
if [[ -z "$SUBCMD" ]]; then
    SUBCMD="build"
fi

# Dispatch
case "$SUBCMD" in
    deps)    cmd_deps    "${PASSTHRU[@]:-}" ;;
    check)   cmd_check   "${PASSTHRU[@]:-}" ;;
    sysctl)  cmd_sysctl  "${PASSTHRU[@]:-}" ;;
    build)   cmd_build   "${PASSTHRU[@]:-}" ;;
    cbmc)    cmd_cbmc    "${PASSTHRU[@]:-}" ;;
    sweep)   cmd_sweep   "${PASSTHRU[@]:-}" ;;
    paper)   cmd_paper   "${PASSTHRU[@]:-}" ;;
    clean)   cmd_clean   "${PASSTHRU[@]:-}" ;;
    all)     cmd_all     "${PASSTHRU[@]:-}" ;;
    *)       err "Unknown sub-command: $SUBCMD"; usage; exit 4 ;;
esac
