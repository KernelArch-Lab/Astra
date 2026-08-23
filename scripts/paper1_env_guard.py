#!/usr/bin/env python3
# =============================================================================
# Astra Runtime - Paper 1 pre-flight environment guard
# scripts/paper1_env_guard.py
#
# Run this BEFORE a sweep. It refuses hosts that would produce numbers you
# cannot publish, and warns about hosts that will produce noisy ones.
#
# The hard failure it exists for: on a multi-socket machine, two benchmark
# cores on different NUMA nodes push the shared-memory ring across the
# socket interconnect. Every latency inflates, nothing errors, and the
# result looks like an expensive capability gate. There is no way to spot
# that in the output afterwards, which is why it is checked here.
#
# Exit codes:
#   0  usable (warnings may still be printed)
#   1  hard failure — do not spend a sweep on this host
#   2  not Linux, nothing to check
#
# Usage:
#   python3 scripts/paper1_env_guard.py
#   ASTRA_BENCH_CPUS=4,6 python3 scripts/paper1_env_guard.py --json env.json
# =============================================================================

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import sys
from pathlib import Path

SYS = Path("/sys")
PROC = Path("/proc")


def read(p: Path) -> str:
    try:
        return p.read_text().strip()
    except OSError:
        return ""


def expandList(spec: str) -> list[int]:
    """Expand a kernel CPU list ('2,4-6') into [2,4,5,6]."""
    out: list[int] = []
    for part in filter(None, (s.strip() for s in spec.split(","))):
        if "-" in part:
            a, _, b = part.partition("-")
            try:
                out.extend(range(int(a), int(b) + 1))
            except ValueError:
                continue
        else:
            try:
                out.append(int(part))
            except ValueError:
                continue
    return sorted(set(out))


def numaMap() -> dict[int, int]:
    """cpu -> numa node."""
    m: dict[int, int] = {}
    for node in sorted(SYS.glob("devices/system/node/node*")):
        mt = re.match(r"node(\d+)$", node.name)
        if not mt:
            continue
        for cpu in expandList(read(node / "cpulist")):
            m[cpu] = int(mt.group(1))
    return m


def benchCpus() -> tuple[list[int], str]:
    env = os.environ.get("ASTRA_BENCH_CPUS", "")
    if env:
        return expandList(env), "ASTRA_BENCH_CPUS"
    iso = read(SYS / "devices/system/cpu/isolated")
    if iso:
        return expandList(iso), "/sys/devices/system/cpu/isolated"
    return [], "none (benchmarks will not pin)"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", type=Path, default=None)
    ap.add_argument("--allow-cross-numa", action="store_true",
                    help="downgrade the cross-socket failure to a warning")
    args = ap.parse_args()

    if platform.system() != "Linux":
        print(f"env_guard: {platform.system()} is not Linux; nothing to check.")
        return 2

    fails: list[str] = []
    warns: list[str] = []
    info: dict = {}

    def say(tag: str, msg: str) -> None:
        print(f"  {tag:<5} {msg}")

    print("=" * 72)
    print("PAPER 1 ENVIRONMENT GUARD")
    print("=" * 72)

    # -- identity --------------------------------------------------------
    model = ""
    for ln in read(PROC / "cpuinfo").splitlines():
        if ln.startswith("model name"):
            model = ln.split(":", 1)[1].strip()
            break
    kernel = platform.release()
    online = expandList(read(SYS / "devices/system/cpu/online"))
    info |= {"model": model, "kernel": kernel, "cpus_online": len(online)}
    print("\n[1] Host")
    say("info", f"{model or 'unknown CPU'}")
    say("info", f"kernel {kernel}, {len(online)} CPUs online")

    # -- virtualisation: decides whether the PMU exists at all -----------
    virt = ""
    hyp = read(SYS / "hypervisor/type")
    flags = read(PROC / "cpuinfo")
    if hyp:
        virt = hyp
    elif " hypervisor" in flags or "\nflags" in flags and "hypervisor" in flags:
        virt = "detected via cpuid"
    info["virtualised"] = bool(virt)
    print("\n[2] Virtualisation")
    if virt:
        say("WARN", f"running virtualised ({virt}); hardware counters are "
                    f"usually unavailable, so Table 2 and section 6.5 will not render")
        warns.append("virtualised host: perf counters likely unavailable")
    else:
        say("ok", "bare metal (no hypervisor detected)")

    # -- the hard one: NUMA locality of the benchmark cores --------------
    cpus, src = benchCpus()
    nm = numaMap()
    nodes = sorted({nm[c] for c in cpus if c in nm})
    info |= {"bench_cpus": cpus, "bench_cpus_source": src,
             "numa_nodes_of_bench_cpus": nodes, "numa_nodes_total": len(set(nm.values()))}
    print("\n[3] Benchmark core locality")
    say("info", f"cores {cpus or '(none)'} from {src}")
    say("info", f"machine has {len(set(nm.values()))} NUMA node(s)")
    if not cpus:
        say("WARN", "no benchmark cores selected; harnesses will run unpinned "
                    "and results will be noisier")
        warns.append("no pinning: set ASTRA_BENCH_CPUS or isolcpus")
    elif len(nodes) > 1:
        msg = (f"benchmark cores span NUMA nodes {nodes}. The IPC ring would "
               f"cross the socket interconnect and every latency would be "
               f"inflated with no visible error.")
        if args.allow_cross_numa:
            say("WARN", msg); warns.append(msg)
        else:
            say("FAIL", msg)
            fails.append(msg)
            say("", "fix: pick cores from one node, e.g. "
                    f"ASTRA_BENCH_CPUS={','.join(str(c) for c in sorted(nm) if nm[c] == nodes[0])[:24]}...")
    else:
        say("ok", f"all benchmark cores on NUMA node {nodes[0] if nodes else '?'}")

    # -- frequency stability --------------------------------------------
    print("\n[4] Frequency stability")
    govs = {read(p) for p in SYS.glob("devices/system/cpu/cpu*/cpufreq/scaling_governor")}
    govs.discard("")
    noTurbo = read(SYS / "devices/system/cpu/intel_pstate/no_turbo")
    boost = read(SYS / "devices/system/cpu/cpufreq/boost")
    info |= {"governors": sorted(govs), "intel_pstate_no_turbo": noTurbo,
             "cpufreq_boost": boost}
    if govs:
        say("ok" if govs == {"performance"} else "WARN",
            f"governor(s): {', '.join(sorted(govs))}")
        if govs != {"performance"}:
            warns.append(f"governor is {sorted(govs)}, not performance")
    else:
        say("WARN", "no cpufreq interface (common on virtualised hosts); "
                    "frequency is not under your control")
        warns.append("no cpufreq control")
    if noTurbo == "0" or boost == "1":
        say("WARN", "turbo/boost is ENABLED. On a thermally limited part this is "
                    "the main source of cross-run variance; a fixed clock below "
                    "the throttle point trades peak speed for reproducibility")
        warns.append("turbo enabled: expect cross-run variance")
    elif noTurbo == "1" or boost == "0":
        say("ok", "turbo/boost disabled")

    # -- SMT -------------------------------------------------------------
    print("\n[5] SMT")
    smt = read(SYS / "devices/system/cpu/smt/control")
    info["smt"] = smt
    if smt in ("on", "forceoff", "off", "notsupported", ""):
        if smt == "on":
            say("WARN", "SMT is ON; a sibling thread can steal from a benchmark core")
            warns.append("SMT on")
        else:
            say("ok", f"SMT: {smt or 'not reported'}")

    # -- isolation flags -------------------------------------------------
    print("\n[6] Kernel isolation")
    cmdline = read(PROC / "cmdline")
    info["cmdline"] = cmdline
    for flag in ("isolcpus", "nohz_full", "rcu_nocbs", "nosmt"):
        present = flag in cmdline
        say("ok" if present else "WARN", f"{flag}: {'present' if present else 'absent'}")
        if not present:
            warns.append(f"{flag} not on the kernel command line")

    # -- PMU access ------------------------------------------------------
    print("\n[7] Performance counters")
    par = read(PROC / "sys/kernel/perf_event_paranoid")
    info["perf_event_paranoid"] = par
    try:
        ok = int(par) <= 1
    except ValueError:
        ok = False
    say("ok" if ok else "WARN",
        f"perf_event_paranoid = {par or 'unreadable'}"
        + ("" if ok else "; bench_perfcounters will self-skip and Table 2 stays a placeholder"))
    if not ok:
        warns.append("perf_event_paranoid > 1: no Table 2")

    # -- steal time ------------------------------------------------------
    print("\n[8] CPU steal")
    steal = None
    for ln in read(PROC / "stat").splitlines():
        if ln.startswith("cpu "):
            parts = ln.split()
            if len(parts) > 8:
                steal = int(parts[8])
            break
    info["steal_ticks"] = steal
    if steal:
        say("WARN", f"non-zero steal time ({steal} ticks); another tenant is "
                    f"taking cycles from this host")
        warns.append("non-zero steal time")
    else:
        say("ok", "no steal time recorded")

    # -- verdict ---------------------------------------------------------
    print("\n" + "=" * 72)
    if fails:
        print(f"VERDICT: DO NOT RUN. {len(fails)} hard failure(s):")
        for i, f in enumerate(fails, 1):
            print(f"  {i}. {f}")
    elif warns:
        print(f"VERDICT: usable, with {len(warns)} caveat(s) to record in section 6.1:")
        for i, w in enumerate(warns, 1):
            print(f"  {i}. {w}")
    else:
        print("VERDICT: clean host. Nothing to disclose beyond the hardware itself.")
    print("=" * 72)

    info |= {"fails": fails, "warns": warns}
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(info, indent=2) + "\n")
        print(f"\nmachine-readable environment -> {args.json}")

    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
