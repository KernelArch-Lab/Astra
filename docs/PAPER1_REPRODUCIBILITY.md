# Paper 1 — Artifact Evaluation Reproducibility

> Companion to `papers/paper1/outline.md`. This document is what the
> USENIX ATC artefact-evaluation reviewer reads. The promise: every
> figure and every numeric claim in Paper 1 is reproduced by **one
> shell command** on a fresh Fedora 39+ x86-64 machine with no internet
> access required for the required (non-optional) baselines.

## TL;DR

```bash
# 0. Verify host has every tool the paper needs:
./scripts/check_paper1_env.sh

# 1. Required tools — install on Fedora 39+:
sudo dnf install -y cmake gcc-c++ nasm liburing-devel cbmc \
                     texlive-scheme-medium \
                     python3-pandas python3-matplotlib python3-numpy

# 2. Run the full sweep (latency + throughput + revoke + perf counters).
#    Five end-to-end repetitions per benchmark (paper methodology);
#    the canonical CSVs are the per-cell MEDIAN across repetitions.
./scripts/run_paper1_sweep.sh            # 5 reps (default)
./scripts/run_paper1_sweep.sh --quick    # 1 rep — smoke test only

# 3. Build the paper PDF — picks up the fresh CSVs, regenerates every
#    figure + numbers.tex + table_1 + table_perf, builds the PDF, and
#    runs the internal review checklist:
cd papers/paper1 && ./build.sh --refresh --check

# Outputs:
#   artefact/environment.txt             host provenance (kernel, governor,
#                                        isolcpus, SMT, compiler, commit)
#   artefact/paper1_cov_report.txt       cross-repetition stability (CoV);
#                                        cells >5% CoV are flagged WARN
#   artefact/paper1_figure_1.csv         RTT measurements (Figure 1)
#   artefact/paper1_pool_scaling.csv     validate vs pool size (Figure 2)
#   artefact/paper1_throughput_mpsc.csv  MPSC scaling (Figure 3)
#   artefact/paper1_revocation.csv       revoke window CDF (Figure 4;
#                                        repetitions concatenated — more
#                                        samples, better CDF)
#   artefact/paper1_perfcounters.csv     cycles / cache misses (Table perf)
#   artefact/_<bench>.repK.csv           raw per-repetition CSVs (kept)
#   papers/paper1/main.pdf               the compiled paper
```

Total wall time on a Xeon Gold 6248: ~70 minutes (5 reps × ~14 min);
`--quick` runs one repetition in ~14 minutes.

> **Prose-only builds (no Linux box):** `papers/paper1/build.sh` also
> works on macOS via [tectonic](https://tectonic-typesetting.github.io)
> (`brew install tectonic`) — it builds the full PDF with red
> placeholder markers wherever measured numbers have not landed yet.

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
   "performance"-governor x86-64 with isolcpus on cores 4–7. The
   sweep runs five repetitions, reports the median, and writes a
   CoV stability report (`artefact/paper1_cov_report.txt`); host
   provenance is captured in `artefact/environment.txt`.
5. ✅ **Every figure has a script.** §3 of the outline maps each
   figure to its script.
6. ✅ **Every claim has evidence.** §4 of the outline maps each
   numeric claim in the paper to a CI-runnable artefact.
7. ✅ **CI gates the proof.** `.github/workflows/ci.yml` runs the
   build, the ctest suite, the sanitizer build, and the CBMC
   monotonicity proof on every push/PR — no PR can break the proof.

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

### Figure 2 — validate() latency vs token-pool occupancy

```bash
cmake --build build --target bench_pool_scaling
./build/tests/bench/bench_pool_scaling > artefact/paper1_pool_scaling.csv
python3 scripts/plot_paper1_figure_2.py artefact/paper1_pool_scaling.csv \
    --pdf papers/paper1/figures/paper1_figure_2.pdf
```

Reports per-call validate() latency at pool occupancies 16, 256,
2048, 4090 — the flat line is the $O(1)$ claim.

### Figure 3 — MPSC throughput scaling

```bash
cmake --build build --target bench_throughput_mpsc
./build/tests/bench/bench_throughput_mpsc > artefact/paper1_throughput_mpsc.csv
python3 scripts/plot_paper1_figure_3_mpsc.py artefact/paper1_throughput_mpsc.csv \
    --pdf papers/paper1/figures/paper1_figure_3_mpsc.pdf
```

### Figure 4 — revocation-latency CDF

```bash
cmake --build build --target bench_revocation_latency
./build/tests/bench/bench_revocation_latency > artefact/paper1_revocation.csv
python3 scripts/plot_paper1_figure_4_revoke.py artefact/paper1_revocation.csv \
    --pdf papers/paper1/figures/paper1_figure_4_revoke.pdf
```

Window = `revoke()` call → first `PERMISSION_DENIED` observed by a
tight-loop producer, across pool occupancies {16, 256, 2048, 4000}.

### T7 ring-footprint invariant (denied request = zero footprint)

```bash
cmake --build build --target test_ipc_sprint5_cap_gate
./build/tests/ipc/test_ipc_sprint5_cap_gate
```

Test 7 prints `write_claim_index unchanged after denies`.

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
