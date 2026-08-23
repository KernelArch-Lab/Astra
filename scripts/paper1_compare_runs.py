#!/usr/bin/env python3
# =============================================================================
# Astra Runtime - Paper 1 run comparator
# scripts/paper1_compare_runs.py
#
# Diffs two run_summary.json files from paper1_run_report.py so a change can
# be judged instead of guessed. Use it to answer questions like "did pinning
# the clock actually reduce variance", "did the server run fix the drift",
# "did enabling SQPOLL move io_uring".
#
# Direction matters and differs per metric, so each one declares whether
# lower is better. A 12% latency rise and a 12% CoV drop are not the same
# news, and the output says so.
#
# Usage:
#   python3 scripts/paper1_compare_runs.py before.json after.json
# =============================================================================

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# metric path -> (label, lower_is_better)
SCALARS = [
    (("headline", "raw_p99"),        "raw RTT p99 (ns)",        True),
    (("headline", "gated_p99"),      "gated RTT p99 (ns)",      True),
    (("headline", "gate_ns"),        "gate cost (ns)",          True),
    (("headline", "gate_pct"),       "gate as % of RTT",        True),
    (("checks",   "cov_over"),       "cells over 5% CoV",       True),
    (("gates",    "o1_flatness_pct"),"validate spread (%)",     True),
]


def dig(d: dict, path: tuple[str, ...]):
    cur = d
    for k in path:
        if not isinstance(cur, dict) or k not in cur:
            return None
        cur = cur[k]
    return cur


def fmtDelta(before, after, lowerBetter: bool) -> str:
    if before in (None, 0) or after is None:
        return "n/a"
    d = after - before
    pct = d / abs(before) * 100
    if abs(pct) < 0.5:
        return f"{d:+.2f} ({pct:+.1f}%)  unchanged"
    better = (d < 0) if lowerBetter else (d > 0)
    return f"{d:+.2f} ({pct:+.1f}%)  {'BETTER' if better else 'WORSE'}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("before", type=Path)
    ap.add_argument("after", type=Path)
    args = ap.parse_args()

    for p in (args.before, args.after):
        if not p.exists():
            print(f"error: {p} not found", file=sys.stderr)
            return 1

    b = json.loads(args.before.read_text())
    a = json.loads(args.after.read_text())

    print("=" * 78)
    print("RUN COMPARISON")
    print(f"  before: {args.before}")
    print(f"  after : {args.after}")
    print("=" * 78)

    print(f"\n{'metric':<26}{'before':>12}{'after':>12}   change")
    print("-" * 78)
    for path, label, lower in SCALARS:
        bv, av = dig(b, path), dig(a, path)
        if bv is None and av is None:
            continue
        bs = f"{bv:.2f}" if isinstance(bv, (int, float)) else "-"
        as_ = f"{av:.2f}" if isinstance(av, (int, float)) else "-"
        print(f"{label:<26}{bs:>12}{as_:>12}   {fmtDelta(bv, av, lower)}")

    # Rounding stability is the decision that drives how the paper quotes
    # the headline, so surface it explicitly rather than as a number.
    print("\nHeadline reproducibility")
    for tag, d in (("before", b), ("after", a)):
        rng = dig(d, ("headline", "gate_range_ns"))
        stable = dig(d, ("headline", "rounding_stable"))
        prints = dig(d, ("headline", "prints_as"))
        if rng:
            state = "stable" if stable else "UNSTABLE across reps"
            print(f"  {tag:<7} prints as {prints} ns, per-rep range "
                  f"{rng[0]}..{rng[1]} ns  ({state})")
        else:
            print(f"  {tag:<7} no per-repetition data")

    # Thermal drift, per benchmark, matched by name.
    print("\nThermal drift (first to last repetition)")
    bd = {d["bench"]: d for d in (dig(b, ("checks", "rep_drift")) or [])}
    ad = {d["bench"]: d for d in (dig(a, ("checks", "rep_drift")) or [])}
    for name in sorted(set(bd) | set(ad)):
        bv = bd.get(name, {}).get("drift_pct")
        av = ad.get(name, {}).get("drift_pct")
        if bv is None or av is None:
            print(f"  {name:<32} {'only in one run':>28}")
            continue
        verdict = "BETTER" if abs(av) < abs(bv) - 0.5 else \
                  "WORSE" if abs(av) > abs(bv) + 0.5 else "unchanged"
        print(f"  {name:<32} {bv:+7.1f}% -> {av:+7.1f}%   {verdict}")

    # Tail ratios per transport.
    print("\nTail ratio p99.99/p50")
    bt = dig(b, ("checks", "tail_ratio")) or {}
    at = dig(a, ("checks", "tail_ratio")) or {}
    for t in sorted(set(bt) | set(at)):
        bv, av = bt.get(t), at.get(t)
        if bv is None or av is None:
            print(f"  {t:<16} {'only in one run':>28}")
            continue
        verdict = "BETTER" if av < bv * 0.9 else "WORSE" if av > bv * 1.1 else "unchanged"
        print(f"  {t:<16} {bv:>10.1f}x -> {av:>10.1f}x   {verdict}")

    # Overall.
    print("\n" + "=" * 78)
    bp, apn = len(b.get("problems", [])), len(a.get("problems", []))
    print(f"Problems: {bp} -> {apn}   "
          f"{'IMPROVED' if apn < bp else 'REGRESSED' if apn > bp else 'unchanged'}")
    fixed = set(b.get("problems", [])) - set(a.get("problems", []))
    new = set(a.get("problems", [])) - set(b.get("problems", []))
    for f in sorted(fixed):
        print(f"  resolved: {f}")
    for n in sorted(new):
        print(f"  NEW:      {n}")
    print("=" * 78)
    return 0


if __name__ == "__main__":
    sys.exit(main())
