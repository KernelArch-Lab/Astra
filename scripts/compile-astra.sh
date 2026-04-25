#!/usr/bin/env bash
# ============================================================================
# Astra Runtime - one-shot build + test driver
#
# Usage:
#   ./scripts/compile-astra.sh              # configure, build, run all tests
#   ./scripts/compile-astra.sh -R Sprint2   # any args forward to ctest
#
# Or wire it to a shell alias:
#   alias compile-astra='~/projects/Astra/scripts/compile-astra.sh'
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BUILD_DIR="$REPO_ROOT/build"
BUILD_TYPE="${ASTRA_BUILD_TYPE:-Debug}"
JOBS="${ASTRA_JOBS:-$(nproc 2>/dev/null || echo 4)}"

echo "==> Configuring (build type: $BUILD_TYPE)"
cmake -S "$REPO_ROOT" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE="$BUILD_TYPE"

echo "==> Building (-j$JOBS)"
cmake --build "$BUILD_DIR" -j"$JOBS"

echo "==> Running tests"
ctest --test-dir "$BUILD_DIR" --output-on-failure "$@"
