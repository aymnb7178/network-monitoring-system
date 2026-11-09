"""Matplotlib (Agg) charts; each function returns PNG bytes."""

from __future__ import annotations

import io

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402

from netmon.anomaly import BIN_S  # noqa: E402
from netmon.flows import EPOCH0  # noqa: E402

BLUE, ORANGE, RED, GREY = "#2563eb", "#ea580c", "#dc2626", "#6b7280"
METHOD_STYLE = {"zscore": ("o", "#7c3aed"), "iforest": ("s", "#0d9488"), "fan_out": ("^", ORANGE),
                "byte_spike": ("D", RED), "beaconing": ("P", BLUE)}


def _png(fig) -> bytes:
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=110, bbox_inches="tight")
    plt.close(fig)
    return buf.getvalue()


def latency_chart(checks: pd.DataFrame) -> bytes:
    fig, ax = plt.subplots(figsize=(8, 3.6))
    t0 = checks["ts"].min()
    for (host, port), g in checks.groupby(["host", "port"]):
        ok = g[g["ok"]]
        ax.plot(ok["ts"] - t0, ok["latency_ms"], marker=".", lw=1, label=f"{host}:{port}")
        bad = g[~g["ok"]]
        if len(bad):
            ax.scatter(bad["ts"] - t0, [0] * len(bad), marker="x", color=RED, zorder=3)
    ax.scatter([], [], marker="x", color=RED, label="failed check")
    ax.set(xlabel="seconds since first check", ylabel="TCP connect latency (ms)", title="Latency over time (localhost listeners)")
    ax.grid(alpha=0.3)
    ax.legend(fontsize=7, ncol=2)
    return _png(fig)


def top_talkers_chart(flows: pd.DataFrame, n: int = 10) -> bytes:
    top = (flows.groupby("src")["bytes"].sum().sort_values(ascending=False).head(n) / 1e6)[::-1]
    fig, ax = plt.subplots(figsize=(7, 3.8))
    ax.barh(top.index, top.values, color=BLUE)
    ax.set(xlabel="total bytes (MB)", title="Top talkers by bytes (SYNTHETIC flows)")
    ax.grid(axis="x", alpha=0.3)
    return _png(fig)


def anomaly_timeline_chart(grid: pd.DataFrame, detections, labels) -> bytes:
    hosts = sorted(grid["host"].unique())
    ypos = {h: i for i, h in enumerate(hosts)}
    fig, ax = plt.subplots(figsize=(9, 4.6))
    for l in labels:
        ax.barh(ypos[l["host"]], (l["end"] - l["start"]) / 3600, left=(l["start"] - EPOCH0) / 3600,
                height=0.8, color="#fecaca", edgecolor=RED, lw=0.6, zorder=1)
    ax.barh([], [], color="#fecaca", edgecolor=RED, label="injected anomaly (ground truth)")
    for m, (mk, col) in METHOD_STYLE.items():
        ds = [d for d in detections if d.method == m]
        if ds:
            ax.scatter([(d.bin * BIN_S + BIN_S / 2 - EPOCH0) / 3600 for d in ds], [ypos[d.host] for d in ds],
                       marker=mk, s=22, color=col, label=m, zorder=3, alpha=0.9)
    ax.set_yticks(range(len(hosts)), hosts, fontsize=7)
    ax.set(xlabel="hours since start", title="Anomaly timeline (SYNTHETIC data, injected anomalies shaded)")
    ax.grid(axis="x", alpha=0.3)
    ax.legend(fontsize=7, loc="upper left", bbox_to_anchor=(1.01, 1))
    return _png(fig)
