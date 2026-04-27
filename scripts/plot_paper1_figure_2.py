#!/usr/bin/env python3
# =============================================================================
# Astra Runtime - Paper 1 Figure 2 plotter (validate latency vs pool size)
# scripts/plot_paper1_figure_2.py
#
# Track B Sprint 8 of the Paper 1 (USENIX ATC 2027) prep work.
#
# Reads paper1_pool_scaling.csv produced by bench_pool_scaling and emits
# the headline O(1) figure: validate() p50/p99/p99.99 plotted against
# token-pool size. The shape of the figure IS the proof of O(1).
#
# Usage:
#   python3 scripts/plot_paper1_figure_2.py artefact/paper1_pool_scaling.csv
# =============================================================================

from __future__ import annotations

import argparse
import sys
from pathlib import Path

try:
    import pandas as pd
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
except ImportError:
    print("error: pandas + matplotlib required", file=sys.stderr)
    sys.exit(1)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("csv", type=Path)
    ap.add_argument("--pdf", type=Path,
                    default=Path("artefact/paper1_figure_2.pdf"))
    args = ap.parse_args()

    df = pd.read_csv(args.csv)
    df = df[df["metric"] == "validate"]
    df = df.sort_values("pool_active")

    fig, ax = plt.subplots(figsize=(6, 3.8))
    ax.plot(df["pool_active"], df["p50_ns"],   marker="o", label="p50",   color="tab:blue")
    ax.plot(df["pool_active"], df["p99_ns"],   marker="s", label="p99",   color="tab:orange")
    ax.plot(df["pool_active"], df["p9999_ns"], marker="^", label="p99.99", color="tab:red")

    ax.set_xscale("log", base=2)
    ax.set_xlabel("Active tokens in pool (max 4096)")
    ax.set_ylabel("validate() per-call latency (ns)")
    ax.set_title("Paper 1 Figure 2 — slot-indexed validate is O(1)")
    ax.grid(which="both", linestyle=":", linewidth=0.5, alpha=0.6)
    ax.legend(loc="upper left", framealpha=0.9, fontsize=10)
    ax.set_ylim(bottom=0)

    fig.tight_layout()
    args.pdf.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(args.pdf, format="pdf")
    print(f"  wrote {args.pdf}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
