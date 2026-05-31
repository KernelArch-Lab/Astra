#!/usr/bin/env bash
# =============================================================================
# Astra Runtime - Paper 1 environment pre-flight
# scripts/check_paper1_env.sh
#
# Verifies the host has every tool the paper-1 sweep + writeup needs.
# Exits 0 if everything required is present; 1 if a required tool is
# missing. Optional tools (Aeron, eRPC) print a note but do not fail.
#
# Usage:
#   ./scripts/check_paper1_env.sh
# =============================================================================
set -u

REQ_FAIL=0

check () {
    local what="$1"; local cmd="$2"; local req="${3:-required}"
    if eval "$cmd" >/dev/null 2>&1; then
        printf "  \033[32mOK\033[0m   %s\n" "$what"
    else
        if [[ "$req" == "required" ]]; then
            printf "  \033[31mFAIL\033[0m %s   (required)\n" "$what"
            REQ_FAIL=1
        else
            printf "  \033[33mSKIP\033[0m %s   (optional — will self-skip)\n" "$what"
        fi
    fi
}

echo "==> Paper 1 environment check"
echo

echo "Linux build toolchain:"
check "cmake ≥ 3.28"      "cmake --version | grep -E 'cmake version 3\.(2[8-9]|[3-9][0-9])'"
check "C++23 compiler"    "echo '#if __cplusplus < 202002L\n#error\n#endif' | c++ -std=c++23 -x c++ -c -o /dev/null -"
check "NASM"              "nasm -v"
check "pthread"           "echo 'int main(){}' | c++ -pthread -x c++ -o /dev/null -"

echo
echo "Linux kernel features:"
check "memfd_create()"    "grep -q memfd_create /proc/kallsyms 2>/dev/null || command -v gcc >/dev/null && echo '#include <sys/mman.h>' | gcc -E -x c - 2>&1 | grep -q MFD_CLOEXEC"
check "perf_event_open ≤ 1" "[[ \$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null) -le 1 ]]"
check "/dev/cpu_dma_latency"  "[[ -e /dev/cpu_dma_latency ]]" optional

echo
echo "Required baselines:"
check "liburing-devel"    "[[ -f /usr/include/liburing.h ]] || ldconfig -p | grep -q liburing"

echo
echo "Optional baselines (skipped if missing):"
check "Aeron headers"     "[[ -n \"\${AERON_DIR:-}\" && -f \"\${AERON_DIR}/aeron-client/src/main/cpp/Aeron.h\" ]]" optional
check "eRPC headers"      "[[ -n \"\${ERPC_DIR:-}\" && -f \"\${ERPC_DIR}/src/rpc.h\" ]]" optional

echo
echo "Verification toolchain:"
check "cbmc ≥ 6.0"        "cbmc --version | grep -qE '^[6-9]\.'"

echo
echo "Plotting toolchain:"
check "python3 ≥ 3.9"     "python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,9) else 1)'"
check "pandas"            "python3 -c 'import pandas'"
check "matplotlib"        "python3 -c 'import matplotlib'"
check "numpy"             "python3 -c 'import numpy'"

echo
echo "LaTeX toolchain (for the paper itself):"
check "pdflatex"          "command -v pdflatex"
check "bibtex"            "command -v bibtex"

echo
echo "Reproducibility nice-to-haves:"
check "performance governor"  "[[ \$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null) == performance ]]" optional
check "isolcpus on cmdline"   "grep -q isolcpus /proc/cmdline" optional
check "HT disabled"           "[[ \$(grep -c 'core id' /proc/cpuinfo) == \$(grep -c '^processor' /proc/cpuinfo) ]]" optional

echo
if [[ $REQ_FAIL -eq 0 ]]; then
    printf "\033[32m==> All required tools present. Ready to run scripts/run_paper1_sweep.sh\033[0m\n"
    exit 0
else
    printf "\033[31m==> Missing required tools above. Install before running the sweep.\033[0m\n"
    echo
    echo "Quick install on Fedora 39+:"
    echo "  sudo dnf install -y cmake gcc-c++ nasm liburing-devel \\"
    echo "                       cbmc texlive-scheme-medium \\"
    echo "                       python3-pandas python3-matplotlib python3-numpy"
    exit 1
fi
