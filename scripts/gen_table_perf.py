#!/usr/bin/env python3
# =============================================================================
# Astra Runtime - Paper 1 Table (perf-counters) generator
# scripts/gen_table_perf.py
#
# Reads paper1_perfcounters.csv (one row per metric × pool size:
# cycles / l1d_miss / llc_miss / branch_miss) and emits a LaTeX
# tabular block for §6.5 of the paper. Output goes to
# papers/paper1/numbers/table_perf.tex via build.sh redirection.
# =============================================================================

from __future__ import annotations
import argparse, csv, sys
from collections import defaultdict
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("csv", type=Path)
    args = ap.parse_args()

    if not args.csv.exists():
        print(r"\textit{paper1\_perfcounters.csv missing — run sweep.}",
              file=sys.stderr)
        # Still emit a placeholder so LaTeX doesn't error.
        print(r"\begin{tabular}{lrrrr}")
        print(r"\toprule")
        print(r"Pool & cycles & L1d-miss & LLC-miss & branch-miss \\")
        print(r"\midrule")
        print(r"\multicolumn{5}{c}{\textit{(no data — run sweep)}} \\")
        print(r"\bottomrule")
        print(r"\end{tabular}")
        return 0

    # rows: metric -> pool_active -> per_iter
    table: dict[str, dict[int, float]] = defaultdict(dict)
    with args.csv.open() as f:
        for r in csv.DictReader(f):
            try:
                pool   = int(r["pool_active"])
                metric = r["metric"]
                table[metric][pool] = float(r["per_iter"])
            except (KeyError, ValueError):
                continue

    if not table:
        print(r"\textit{paper1\_perfcounters.csv had no usable rows.}")
        return 0

    pools = sorted({p for m in table.values() for p in m.keys()})

    print(r"\begin{tabular}{l" + "r" * len(pools) + "}")
    print(r"\toprule")
    print(r"Metric (per validate)" +
          "".join(f" & {p}-pool" for p in pools) + r" \\")
    print(r"\midrule")
    for metric in ("cycles", "l1d_miss", "llc_miss", "branch_miss"):
        if metric not in table:
            continue
        nice = {
            "cycles":     "cycles",
            "l1d_miss":   "L1d miss",
            "llc_miss":   "LLC miss",
            "branch_miss":"branch miss",
        }[metric]
        cells = []
        for p in pools:
            v = table[metric].get(p)
            cells.append(f"{v:.2f}" if v is not None else "—")
        print(f"{nice} & " + " & ".join(cells) + r" \\")
    print(r"\bottomrule")
    print(r"\end{tabular}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
