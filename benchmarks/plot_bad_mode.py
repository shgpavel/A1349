#!/usr/bin/env python3
"""
plot_bad_mode.py - Redraw the stress-tail chart of docs/case-study-i7-1260p.md.

One point per full-length stress run (schbench -m 4 -t 32, 30 s): schbench
request p99 per scx_A1349 config, coloured and shaped by session, with the
85 ms bad-mode cut-off and the count of runs above it. Reads the run meta.json
files of the i7-1260P sessions under results/ (gitignored, so this only works
on the machine that ran them).

Usage:
    plot_bad_mode.py [OUT.png]     (default: docs/img/stress-request-p99-per-run.png)
"""

import glob
import json
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
R = REPO / "results"
CUT = 85

CONFIGS = [
    ("as-is\n(no P/E fix)", [
        ("Oct 2", R / "20261002_194830/stress/run*/scx_A1349"),
        ("Oct 3", R / "tune/final_i7/stress/run*/scx_A1349_asis"),
        ("Oct 3", R / "tune/D_stress_tail/stress/run*/asis"),
    ]),
    ("P/E fix, 20 ms\n(stock)", [
        ("Oct 3", R / "tune/D_stress_tail/stress/run*/hyb20"),
        ("Oct 4", R / "20261004_003922/stress/run*/scx_A1349"),
    ]),
    ("P/E fix, 30 ms", [
        ("Oct 3", R / "tune/final_i7/stress/run*/scx_A1349"),
        ("Oct 3", R / "tune/D_stress_tail/stress/run*/hyb30"),
    ]),
]
# Session -> (colour, marker, legend label). Colours are validated categorical
# slots 1-3; the marker shape carries identity too.
SESSIONS = {
    "Oct 2": ("#2a78d6", "o", "Oct 2 (rc4)"),
    "Oct 3": ("#eb6834", "s", "Oct 3 (rc4)"),
    "Oct 4": ("#1baf7a", "^", "Oct 4 (rc5, LLVM 23)"),
}
SURFACE, INK, INK2, MUTED, GRID, AXIS = (
    "#fcfcfb", "#0b0b0b", "#52514e", "#898781", "#e1e0d9", "#c3c2b7")


def p99_ms(pattern):
    vals = []
    for d in sorted(glob.glob(str(pattern))):
        metas = sorted(glob.glob(d + "/*.meta.json"))
        if not metas:
            continue
        m = json.loads(Path(metas[-1]).read_text())
        if m.get("complete") and m.get("sched_ext_ok") and m.get("oneshot_runs"):
            v = m["oneshot_runs"][0].get("schbench_request_p99_0_usec")
            if v:
                vals.append(v / 1000)
    return vals


def main():
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else (
        REPO / "docs" / "img" / "stress-request-p99-per-run.png")

    fig, ax = plt.subplots(figsize=(8, 4.6), dpi=200)
    fig.patch.set_facecolor(SURFACE)
    ax.set_facecolor(SURFACE)

    seen = set()
    labels = []
    for i, (cfg, sets) in enumerate(CONFIGS):
        allv = []
        centers = [i] if len(sets) == 1 else [
            i - 0.27 + 0.54 * j / (len(sets) - 1) for j in range(len(sets))]
        for (sess, pat), cx in zip(sets, centers, strict=True):
            vals = p99_ms(pat)
            allv += vals
            col, mk, lab = SESSIONS[sess]
            xs = [cx + (k - (len(vals) - 1) / 2) * 0.045 for k in range(len(vals))]
            ax.scatter(xs, vals, s=46, marker=mk, color=col, edgecolors=SURFACE,
                       linewidths=1.6, zorder=3, label=None if sess in seen else lab)
            seen.add(sess)
        bad = sum(v > CUT for v in allv)
        labels.append(f"{cfg}\n{bad} of {len(allv)} runs > {CUT} ms")

    ax.axhline(CUT, color=INK2, lw=1.2, ls=(0, (4, 3)), zorder=2)
    ax.text(-0.55, CUT + 2.5, f"bad-mode cut-off, {CUT} ms", ha="left",
            va="bottom", color=INK2, fontsize=8.5)

    ax.set_xticks(range(len(CONFIGS)))
    ax.set_xticklabels(labels, color=INK, fontsize=9)
    ax.set_xlim(-0.6, len(CONFIGS) - 0.4)
    ax.set_ylim(0, 120)
    ax.set_ylabel("schbench request p99 (ms)", color=INK2, fontsize=9.5)
    ax.tick_params(axis="y", colors=MUTED, labelsize=8.5)
    ax.tick_params(axis="x", length=0, pad=8)
    ax.grid(axis="y", color=GRID, lw=0.8, zorder=0)
    for s in ("top", "right", "left"):
        ax.spines[s].set_visible(False)
    ax.spines["bottom"].set_color(AXIS)
    ax.set_title("Stress level, one point per full-length run (schbench -m 4 -t 32, 30 s)",
                 loc="left", color=INK, fontsize=10.5, pad=12)
    ax.legend(loc="upper left", frameon=False, fontsize=8.5, labelcolor=INK2,
              handletextpad=0.3, borderaxespad=0.2)
    fig.text(0.01, 0.01, "Kernel default on the same runs: 0.7-1.2 s (off-scale).",
             color=MUTED, fontsize=8)
    fig.tight_layout(rect=(0, 0.03, 1, 1))
    out.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out, facecolor=SURFACE)
    print(out, [lbl.replace("\n", " | ") for lbl in labels])
    return 0


if __name__ == "__main__":
    sys.exit(main())
