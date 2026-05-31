#!/usr/bin/env python3
# =============================================================================
# Astra Runtime - Paper 1 Figure 3 plotter (MPSC throughput scaling)
# scripts/plot_paper1_figure_3_mpsc.py
#
# Reads paper1_throughput_mpsc.csv and emits a two-line plot showing
# aggregate throughput vs producer count for the gate-OFF and gate-ON
# arms. Linear scaling = good. A super-linear knee = the wait-free
# fetch_add path saturating the cache line; a flat ceiling = the
# CAS path.
# =============================================================================

from __future__ import annotations
import argparse, sys
from pathlib import Path

try:
    import pandas as pd
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
except ImportError:
    print("error: pandas + matplotlib required", file=sys.stderr); sys.exit(1)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("csv", type=Path)
    ap.add_argument("--pdf", type=Path,
                    default=Path("artefact/paper1_figure_3_mpsc.pdf"))
    args = ap.parse_args()

    df = pd.read_csv(args.csv)
    df = df.sort_values(["transport", "producers"])

    fig, ax = plt.subplots(figsize=(6, 3.8))
    for transport, grp in df.groupby("transport"):
        if transport == "astra_raw":
            label, color, ls = "gate OFF", "tab:green", "--"
        elif transport == "astra_gated":
            label, color, ls = "gate ON",  "tab:orange", "-"
        else:
            continue
        ax.plot(grp["producers"], grp["msgs_per_s"] / 1e6,
                marker="o", label=label, color=color, linestyle=ls,
                linewidth=2)

    ax.set_xscale("log", base=2)
    ax.set_xticks([1, 2, 4, 8, 16])
    ax.get_xaxis().set_major_formatter(matplotlib.ticker.ScalarFormatter())
    ax.set_xlabel("Producers (one consumer)")
    ax.set_ylabel("Aggregate throughput (M msg/s)")
    ax.set_title("Paper 1 Figure 3 — MPSC throughput scaling")
    ax.grid(linestyle=":", linewidth=0.5, alpha=0.6)
    ax.legend(loc="upper left", fontsize=10)
    ax.set_ylim(bottom=0)

    fig.tight_layout()
    args.pdf.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(args.pdf, format="pdf")
    print(f"  wrote {args.pdf}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
