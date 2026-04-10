#!/usr/bin/env bash
# fix_clang21.sh — Fix Clang 21 compilation errors
# 1. result.h: use __cpp_lib_expected instead of __has_include(<expected>)
# 2. log.h: add format attribute, replace ##__VA_ARGS__ with __VA_OPT__
set -euo pipefail

echo "[*] Applying Clang 21 compilation fixes..."

# --- 1. result.h: swap __has_include guards to __cpp_lib_expected -----------
RESULT_H="include/astra/common/result.h"
echo "[1/2] Patching $RESULT_H ..."

# Replace the two __has_include(<expected>) guards INSIDE namespace astra
# (lines that control the aliases vs polyfill) with __cpp_lib_expected.
# The top-level #if __has_include(<expected>) that does #include <expected>
# stays as-is — we still want to include the header so it can define the macro.
sed -i '
/^#if __has_include(<expected>)$/{
  # If the NEXT line is #include <expected>, leave this block alone (it is the include guard)
  N
  /\n#include <expected>/{ P; D; }
  # Otherwise this is an alias guard — replace with __cpp_lib_expected
  s/^#if __has_include(<expected>)\n/#ifdef __cpp_lib_expected\n/
}
' "$RESULT_H"
echo "  [OK] result.h patched (__cpp_lib_expected)"

# --- 2. log.h: format attribute + __VA_OPT__ --------------------------------
LOG_H="include/astra/common/log.h"
echo "[2/2] Patching $LOG_H ..."

# 2a. Add __attribute__((format(printf, 5, 6))) before the write function
sed -i '/^inline void write($/i __attribute__((format(printf, 5, 6)))' "$LOG_H"

# 2b. Replace ##__VA_ARGS__ with __VA_OPT__(,) __VA_ARGS__
sed -i 's/, ##__VA_ARGS__)/ __VA_OPT__(,) __VA_ARGS__)/g' "$LOG_H"

echo "  [OK] log.h patched (format attribute + __VA_OPT__)"

echo "========================================="
echo "[+] All Clang 21 fixes applied."
echo "========================================="
echo "Commit and push:"
echo "  git add -A"
echo '  git commit -m "Fix Clang 21: __cpp_lib_expected guard, format attr, __VA_OPT__"'
echo "  git push origin main"
