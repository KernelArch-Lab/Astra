# Paper 1 — Capability-Gated Zero-Copy IPC

LaTeX source for *Capability-Gated Zero-Copy IPC: Sub-Microsecond
Validated Message Delivery on Stock Linux*, targeting USENIX ATC 2027.

This directory contains the entire paper. The benchmarks that produce
its numbers live in `tests/bench/` and `tests/ipc/`; the reproducibility
harness that drives them lives in `scripts/run_paper1_sweep.sh`.

---

## Quick start

Three commands take you from a clean clone to a venue-ready PDF, on a
Linux x86\_64 host with the prerequisites from
`scripts/check_paper1_env.sh`:

```bash
./scripts/check_paper1_env.sh              # verify pdflatex, matplotlib, etc.
./scripts/run_paper1_sweep.sh              # every benchmark × 5 reps → artefact/*.csv
papers/paper1/build.sh --refresh --check   # figures + numbers + PDF + checklist
```

On a host without the benchmark prerequisites (e.g. macOS for
writing only), `papers/paper1/build.sh` (no `--refresh`) builds a
structurally-complete PDF with red `[placeholder]` markers wherever
real measurements should land. Useful for iterating on prose.
`build.sh` auto-detects the engine: `pdflatex`+`bibtex` when
available, otherwise `tectonic` (`brew install tectonic` on macOS).
The USENIX style file is vendored (`usenix-2020-09.sty`) so a cold
clone builds with no manual downloads.

---

## Build modes

```
./build.sh              build PDF, assume figures/numbers exist or stub them
./build.sh --refresh    re-run sweep + plotters first, then build
./build.sh --check      after building, run the internal review checklist
                        (undefined citations, ?? refs, overfull boxes, page
                        count, stub figures, unfilled headline numbers)
./build.sh --anon       force anonymous version
./build.sh --camera     force camera-ready (overrides \anontrue in main.tex)
```

`--anon` is the default per `\anontrue` in `main.tex`.

---

## File layout

```
main.tex                root document, two-column USENIX style
macros.tex              \sysname, \validateTail etc. — placeholder numbers
                        default to red [todoNum] markers
bibliography.bib        36 entries (Aeron, seL4, Cornucopia, eRPC,
                        HongMeng, CAP-VMs, LITESHIELD, …)

sections/
  00_abstract.tex       Abstract — uses \gateOverheadTail, \aeronGapPercent
  01_intro.tex          Intro + contribution list
  02_threat_model.tex   Threat model + non-goals
  03_background.tex     IPC and capability primer
  04_design.tex         Slot-indexed validate + cap gate design
  05_implementation.tex M-21 NASM + M-01 fast path + CBMC proof
  06_evaluation.tex     5 evaluation axes (RTT / O(1) / MPSC / revoke / perf)
  07_discussion.tex     Aeron gap, HongMeng comparison, C++ debate
  08_related_work.tex   Citations split into kernel, hardware, userspace
  09_conclusion.tex     One column

figures/
  Makefile              produces all .pdf figures from artefact/*.csv
  gate_path.tex         TikZ source for the in-text design diagram
  *.pdf                 generated; ignored in git

numbers/
  numbers.tex           \renewcommand overrides for macros.tex numerics
  table_1.tex           p50/p99/p99.99 table at 256 B
  table_perf.tex        L1d/LLC/branch miss table
  (all generated; ship as placeholders so cold-clone build works)

submission/
  anonymize.sh          strip authorship before submission
  cover_letter.md       template
  author_response_template.md   for the response phase

outline.md              section-by-section plan, claim-to-evidence map,
                        venue ladder. Locked 2026-04-27.
```

---

## How numbers flow into the PDF

```
benchmarks (C++) ───run_paper1_sweep.sh───▶ artefact/*.csv
                                                 │
                ┌────────────────────────────────┼───────────────────┐
                ▼                                ▼                   ▼
        plot_paper1_figure_*.py        gen_numbers_tex.py    gen_table_perf.py
                │                                │                   │
                ▼                                ▼                   ▼
        figures/*.pdf                   numbers/numbers.tex   numbers/table_perf.tex
                │                                │                   │
                └──────────┬─────────────────────┴───────────────────┘
                           ▼
                     pdflatex main.tex
                           │
                           ▼
                       main.pdf
```

`build.sh --refresh` runs everything to the left of the diagram;
`build.sh` (no flags) assumes those artefacts exist (or stubs them).

---

## What "complete" means here

The paper is **structurally complete** — every section drafted, every
citation resolved, every figure-include and cross-reference wired,
every macro defined. You can `./build.sh` and get a buildable PDF
that shows the full skeleton.

The paper is **not numerically complete** until somebody runs
`run_paper1_sweep.sh` on a tuned Linux host. The TODO macros and
placeholder figures are deliberately rendered in red so reviewers
(and authors) can see at a glance what is unfilled.

What remains in calendar terms before submission (updated 2026-07-15):

1. **The measured sweep** on the tuned Fedora/Xeon host:
   `./scripts/run_paper1_sweep.sh` (5 reps, ~70 min) then
   `papers/paper1/build.sh --refresh --check` — fills every red
   placeholder, regenerates all four data figures, and re-runs the
   checklist. This is the only step that requires the lab machine.
2. Author list, affiliations, acknowledgements (`main.tex`, camera-ready
   only — the submission stays anonymous).
3. Final pass on §7 Discussion once the actual Aeron-gap number is
   known, and fill the one manual number in §6.3 (`\todoNum{N}` — the
   MPSC saturation point read off Figure 3).
4. AE artefact submission (separate from the paper PDF) — covered by
   `docs/PAPER1_REPRODUCIBILITY.md`.
5. Open decisions from `outline.md` §7: byline, macrobench-in-or-out
   (outline recommends defer), anonymous artifact mirror.

Everything else — buildable LaTeX (pdflatex *and* tectonic), vendored
style file, anonymization pipeline, CI gates (build/ctest/sanitizers/
CBMC/paper), repetition + CoV methodology, environment capture,
LICENSE — is done and verified.

---

## Internal review checklist

`./build.sh --check` runs the mechanical items automatically.
Status as of 2026-07-15 (pre-sweep):

- [x] `./build.sh` succeeds end-to-end (tectonic on macOS; pdflatex on Linux)
- [ ] `./build.sh --refresh` succeeds end-to-end (needs the Linux sweep)
- [ ] No red `[todoNum]` markers remain in the final PDF (needs the sweep)
- [ ] All four data figures real, not stubs (needs the sweep)
- [x] Bibliography has 0 "undefined citation" warnings
- [x] No overfull hboxes beyond the placeholder-driven one in §6
- [x] Page count ≤ venue limit (11 pp incl. refs pre-numbers; 12 excl. refs allowed)
- [x] `submission/anonymize.sh` produces a clean anonymized variant
      (verified: builds standalone, zero identifying strings)
- [x] CBMC proof still passes (0 of 37 failed — verified macOS + Linux container)
- [x] No unresolved `\Cref{?}` markers

---

## Where the prose came from

This draft was authored 2026-04-27 in `feature/paper1-writeup` and
landed on `main` via the Track-B sprint stack documented in
`docs/PUBLICATION_STRATEGY.md`. The 10 sprints behind it:

| Sprint | What it added | Branch |
|---|---|---|
| 4 | M-01 O(1) validate fast path | `feature/m01-validate-fastpath` |
| 5 | M-03 capability-gated IPC fastpath | `feature/m03-cap-gate-wiring` |
| 6 | Baseline harnesses (pipe / socket / io_uring / Aeron / eRPC) | `feature/paper1-baselines` |
| 7 | Sweep + Figure 1 plotter + outline | `feature/paper1-sweep` |
| 8 | Throughput / MPSC / revocation / perf-ctr / pool-scaling benches | `feature/paper1-metrics` |
| 9 | Concurrency / survivability / property / fuzz tests | `feature/paper1-tests` |
| 10 | LaTeX draft + bibliography + build pipeline | `feature/paper1-writeup` |
| (parallel) | M-21 NASM ports + CBMC monotonicity proof + RDTSC bench | `feature/m21-nasm-ports` |

All ten sprints are merged into `main` as of 2026-05-15.

---

## Contact

KernelArch Labs — Shiva, M-01 owner.
For the publication strategy and venue ladder beyond Paper 1, see
[../../docs/PUBLICATION_STRATEGY.md](../../docs/PUBLICATION_STRATEGY.md).
