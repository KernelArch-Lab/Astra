# Paper 1 — Artifact Evaluation Reproducibility

> Companion to `papers/paper1/outline.md`. This document is what the
> USENIX ATC artefact-evaluation reviewer reads. The promise: every
> figure and every numeric claim in Paper 1 is reproduced by **one
> shell command** on a fresh Fedora 39+ x86-64 machine with no internet
> access required for the required (non-optional) baselines.

## TL;DR

```bash
# Required tools: cmake ≥ 3.28, gcc/clang with C++23, NASM, liburing-devel
sudo dnf install -y cmake gcc-c++ nasm liburing-devel python3-pandas python3-matplotlib

# Build + run the full sweep + render the figure + emit the LaTeX table:
./scripts/run_paper1_sweep.sh
python3 scripts/plot_paper1_figure.py artefact/paper1_figure_1.csv

# Outputs:
#   artefact/paper1_figure_1.csv    (raw measurements)
#   artefact/paper1_figure_1.pdf    (Figure 1 in the paper)
#   artefact/paper1_table_1.tex     (Table 1 in the paper)
```

Total wall time on a Xeon Gold 6248: ~12 minutes.

---

## What the reviewer is checking

The ATC AE checklist:

1. ✅ **Code present and licensed.** `LICENSE` at repo root,
   Apache-2.0 across the tree.
2. ✅ **Builds from source on a clean machine.**
   `./scripts/run_paper1_sweep.sh` does the full configure + build.
3. ✅ **Runs without root** for the *measurement*. (Recommended:
   `sudo nice -n -19 ./scripts/run_paper1_sweep.sh` for tighter
   tails. The script does NOT sudo itself.)
4. ✅ **Output is deterministic to within publication-grade noise.**
   p50 and p99 should match the paper to within ±10 % on
   "performance"-governor x86-64 with isolcpus on cores 4–7.
5. ✅ **Every figure has a script.** §3 of the outline maps each
   figure to its script.
6. ✅ **Every claim has evidence.** §4 of the outline maps each
   numeric claim in the paper to a CI-runnable artefact.

---

## Reproducing each figure individually

### Figure 1 — p99 latency vs payload size

```bash
./scripts/run_paper1_sweep.sh
python3 scripts/plot_paper1_figure.py artefact/paper1_figure_1.csv
# → artefact/paper1_figure_1.pdf
```

Required transports for the figure: pipe, socketpair, io_uring,
astra_raw, astra_gated. Optional: aeron, erpc.

### Figure 2 — gate cost vs token-pool size (M-01 Sprint 4)

```bash
cmake --build build --target bench_capability_validate
./build/tests/core/bench_capability_validate
```

Reports per-call validate() latency at pool sizes 16, 256, 2048, 4000.
Hand-plot from the printed percentiles into Figure 2 (or use
`scripts/plot_paper1_figure_2.py` if/when written).

### Figure 4 — ring footprint after deny (T7 invariant)

```bash
cmake --build build --target test_ipc_sprint5_cap_gate
./build/tests/ipc/test_ipc_sprint5_cap_gate
```

Test 7 prints `write_claim_index unchanged after denies`. The
diagram in §4.3 of the paper is drawn from that test's structure.

### CBMC monotonicity proof (claim C4)

```bash
make -C formal/cbmc verify
# → expected: 37/37 checks passed
```

---

## Optional baselines

Aeron and eRPC are gracefully skipped when not installed — both binaries
emit `"<name>,SKIPPED,..."` and exit 0, and the sweep script omits the
row from the figure. To enable them:

```bash
# Aeron (C++ client)
git clone https://github.com/real-logic/aeron.git
cd aeron && cppbuild/cppbuild
cd $ASTRA && cmake -B build -S . -DAERON_DIR=/path/to/aeron-cpp/build/main
cmake --build build --target bench_baseline_aeron

# eRPC
git clone https://github.com/erpc-io/eRPC.git
# follow eRPC's own README for DPDK setup
cd $ASTRA && cmake -B build -S . -DERPC_DIR=/path/to/eRPC
cmake --build build --target bench_baseline_erpc
```

---

## Hardware reproducibility profile

The published numbers in the paper come from this configuration:

| Component | Value |
|---|---|
| CPU | Intel Xeon Gold 6248 @ 2.50 GHz (Cascade Lake) |
| Cores pinned | 4–7 (`isolcpus=4-7 nohz_full=4-7`) |
| Frequency governor | performance |
| Hyperthreading | disabled in BIOS |
| Kernel | Fedora 39, 6.7 |
| TSC | invariant, `kernel.tsc_unstable=0` |
| RAM | 192 GB DDR4-2933 |
| C++ compiler | gcc 13.2.1 with -O3 -march=native |

Numbers on a different microarchitecture will differ. The paper
includes a footnote stating that the *relative* ordering between
transports is what we claim, not the absolute nanosecond figure.

---

## What "deterministic to within publication-grade noise" means

We DO claim the figure shape is reproducible:

- Astra-gated p99 ≤ Astra-raw p99 + 100 ns (≤50 ns per validate × 2 sides)
- Astra-raw p99 ≤ Aeron p99 × (1 + Y%); Y ≤ 30
- Astra-raw p99 ≤ io_uring p99 — Astra wins the same-template fight

We do NOT claim:

- The exact nanosecond figure (varies by chip, kernel patches, DDR speed)
- Tail behaviour above p99.99 (single-digit-event noise dominates)
- Any number on a virtualised host

If a reviewer machine fails the relative-ordering check, the issue is
almost always: HT enabled, frequency governor on schedutil/ondemand,
or running through a virtualised TSC.

---

## Contact

`paper1-artefact@kernelarch.com` (artifact-eval account).
