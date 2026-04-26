# ============================================================================
# Astra Runtime - formal/cbmc - Makefile
#
# Drives CBMC against the capability-monotonicity proof harness.
#
# Usage:
#   make verify         — run all checks; non-zero exit on failure
#   make verify-trace   — also print a counterexample trace if any check fails
#   make clean          — remove .out/.json artefacts
#
# Requires CBMC 5.x or 6.x.
#   Fedora:  sudo dnf install cbmc
#   Ubuntu:  sudo apt install cbmc
# ============================================================================

CBMC ?= cbmc

# Common flags applied to every invocation:
#   --bounds-check        check array indexing
#   --pointer-check       check pointer derefs
#   --signed-overflow-check
#   --unsigned-overflow-check
#   --conversion-check
#   --unwind 4            max loop unwinding (chain proof has nested calls)
#   --depth 50000         exploration depth budget
COMMON_FLAGS := \
    --bounds-check \
    --pointer-check \
    --signed-overflow-check \
    --unsigned-overflow-check \
    --conversion-check \
    --unwind 4 \
    --depth 50000

.PHONY: verify verify-trace clean help

verify: capability_monotonicity.c
	@echo "[CBMC] proving capability monotonicity..."
	$(CBMC) $(COMMON_FLAGS) capability_monotonicity.c
	@echo "[CBMC] PASS — capability monotonicity holds."

verify-trace: capability_monotonicity.c
	@echo "[CBMC] proving capability monotonicity (trace mode)..."
	$(CBMC) $(COMMON_FLAGS) --trace capability_monotonicity.c

clean:
	rm -f *.out *.json

help:
	@echo "make verify         run the proof; exits 0 on success"
	@echo "make verify-trace   run with --trace for counterexamples"
	@echo "make clean          remove generated artefacts"
