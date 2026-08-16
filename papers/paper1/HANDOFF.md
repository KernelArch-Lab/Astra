# Paper 1 — session handoff

State as of 2026-08-16. Read this first when picking the work back up;
it is written to be self-contained.

## Where the paper stands

Engineering, prose, proof, figures, CI, and the artefact pipeline are
done. The draft builds to 12 pages with every figure real, zero
undefined citations, zero unresolved cross-references, and an
anonymised submission tarball that rebuilds standalone.

One command does the whole thing on the Fedora box:

```bash
./scripts/compile-astra.sh paper1        # --quick for a 1-rep smoke run
```

deps → sysctls → governor → Aeron autobuild → Release build → ctest →
CBMC → 5-repetition sweep → figures + numbers → PDF + checklist →
anonymised tarball → summary with thesis-gate verdicts.

## Measured numbers

i7-11370H (4C/8T, Tiger Lake), Fedora 43, kernel 7.0.10, gcc 15.2.1,
`nosmt isolcpus=2,3 nohz_full=2,3 rcu_nocbs=2,3`, performance governor,
5 repetitions median-merged.

| Metric | Value |
|---|---|
| Gate cost, p99 | **7 ns** (design target was ≤50) |
| Gate as share of RTT | 20% |
| Astra raw / gated, 256 B p99 | 67 / 80 ns |
| Revocation time-to-effect, p99 | **0.4 µs** |
| validate p50 / p99 / p99.99 | 21 / 22 / 27 ns |
| pipe / io_uring, 256 B p99 | 5,535 / 6,324 ns |
| Aeron | pending re-run (see below) |
| ctest / CBMC | 21/21 pass, 0 of 37 failed |

## What is left

1. **Re-run for Aeron — the fix is still untested.** Aeron timed out
   twice under core isolation: its client adds a conductor thread to our
   measuring and echo threads, and two isolated cores under `nohz_full`
   leave no preemption for the third. `b7b477a` makes Aeron run
   unpinned. **The 18:24 Fedora run does not test that fix**: its pull
   landed on `8478ebc` (18:07) and `b7b477a` was not committed until
   18:29, so it built the old pinned harness and timed out again exactly
   as before. Before reading anything into a third Aeron timeout,
   check `git log -1 --format=%h` on the box is at or past `b7b477a`.
   That run did fill the other ten macros; only `\aeronRTT` and
   `\aeronGapPercent` are still red. §6.8 documents why that row is
   measured differently.
2. **Byline and affiliations** in `main.tex` — camera-ready only, the
   submission stays anonymous.
3. **Two manual numbers**: `\todoNum{N}` in §6.3 (MPSC saturation point,
   read off Figure 3) and the O(n)-scan comparison in §6.2.
4. **§7 Discussion final pass** now the Aeron number is known.
5. **Macrobench in or out** — `outline.md` §7 recommends defer.

## Things worth knowing before changing anything

- **The machine is laptop-class** and CoV warnings have plateaued near
  80, which points at thermal limits rather than tuning. A server-class
  host would materially strengthen the final numbers. §6.1 describes the
  current machine honestly; update it if the hardware changes. §6.2 used
  to claim a cell past 5% "would have been flagged and re-measured" —
  untrue with 80 flagged and none re-measured — so it now states the
  overshoot outright and points at the shipped CoV report.
- **A clean clone has no data.** `artefact/` and
  `papers/paper1/{main.pdf,figures/*.pdf}` are gitignored, and
  `numbers/*.tex` ship as empty placeholders. On a host that has never
  run the sweep, `build.sh` substitutes four *identical* copies of one
  "[Figure placeholder]" box for the data figures — and the checklist's
  "no stub figures — all figures are real" line only counts
  `figures/*.STUB` sidecars, so it reports all-real once those sidecars
  are gone. Never read a PDF built off a non-Fedora box as evidence the
  figures are real; `md5 figures/*.pdf` showing four matching hashes
  means they are placeholders.
- **isolcpus does not move threads onto the isolated cores** — the
  benchmarks pin explicitly via `astra_bench::pinSelf()`, reading
  `ASTRA_BENCH_CPUS` or `/sys/devices/system/cpu/isolated`. Before that
  existed, isolation made everything *worse*. Do not remove the pinning
  without also amending §6.1.
- **Thread count per harness matters.** Pin blindly and harnesses with
  more threads than cores starve: that is what wedged Aeron and what
  inflated revocation from 0.4 µs to 281 µs when `main()` shared a core
  with the busy producer.
- **io_uring runs without SQPOLL by default.** SQPOLL dedicates a kernel
  poller per ring and measured *slower* here; it is opt-in via
  `ASTRA_IOURING_SQPOLL=1` and §6.8 explains the trade.
- **Aeron is a substrate sanity check, not a scalp.** We measure faster
  than it; §6.2 and §7.2 say plainly that this is because we do less
  (no media-driver decoupling, no network transport, no flow control).
  Do not turn that into a superiority claim.

## Rebuilding just the paper

```bash
cd papers/paper1
./build.sh --check          # PDF + internal review checklist
./build.sh --plots --check  # regenerate figures from existing CSVs, no sweep
./submission/anonymize.sh   # double-blind tarball
```

macOS works for prose via tectonic (`brew install tectonic`); benchmarks
are Linux-only.
