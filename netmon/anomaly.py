"""Anomaly detection on per-host, per-bin flow features: rolling z-score, IsolationForest and rule detectors."""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

BIN_S = 300
FEATURES = ["bytes", "packets", "uniq_dst_ports", "uniq_dst_hosts"]
RULE_METHODS = ("fan_out", "byte_spike", "beaconing")


@dataclass(frozen=True)
class Detection:
    host: str
    bin: int
    method: str
    score: float
    detail: str

    def bin_start(self, bin_s: int = BIN_S) -> int:
        return self.bin * bin_s


def build_features(flows: pd.DataFrame, bin_s: int = BIN_S) -> pd.DataFrame:
    """One row per (host, time bin) over the full grid; bins with no traffic are zeros."""
    f = flows.assign(bin=(flows["ts"] // bin_s).astype(int))
    g = f.groupby(["src", "bin"]).agg(
        flows=("dst", "size"), bytes=("bytes", "sum"), packets=("packets", "sum"),
        uniq_dst_ports=("dst_port", "nunique"), uniq_dst_hosts=("dst", "nunique"),
    )
    idx = pd.MultiIndex.from_product([sorted(f["src"].unique()), range(int(f["bin"].min()), int(f["bin"].max()) + 1)],
                                     names=["src", "bin"])
    return g.reindex(idx, fill_value=0).reset_index().rename(columns={"src": "host"})


def zscore_detect(grid: pd.DataFrame, window: int = 12, min_periods: int = 6, thresh: float = 3.5,
                  cols=("bytes", "uniq_dst_ports", "uniq_dst_hosts")) -> list[Detection]:
    """Upward z-score against the previous `window` bins of the same host (std floored to avoid divide-by-~0)."""
    out = []
    for host, g in grid.groupby("host"):
        for c in cols:
            s = g[c].astype(float)
            prev = s.shift(1)
            mu = prev.rolling(window, min_periods=min_periods).mean()
            sd = prev.rolling(window, min_periods=min_periods).std().fillna(0.0)
            sd = np.maximum(sd, np.maximum(0.1 * mu, 1.0))
            z = (s - mu) / sd
            for b, zv in zip(g.loc[z > thresh, "bin"], z[z > thresh]):
                out.append(Detection(str(host), int(b), "zscore", float(zv), f"{c} z={zv:.1f}"))
    return out


def iforest_detect(grid: pd.DataFrame, contamination: float = 0.01, seed: int = 0) -> list[Detection]:
    """IsolationForest on log1p(per-host features); flags roughly `contamination` of all host-bins."""
    X = np.log1p(grid[FEATURES].to_numpy(dtype=float))
    model = IsolationForest(n_estimators=200, contamination=contamination, random_state=seed).fit(X)
    pred = model.predict(X)
    score = -model.score_samples(X)
    return [Detection(str(r.host), int(r.bin), "iforest", float(s), "isolation score")
            for r, p, s in zip(grid.itertuples(), pred, score) if p == -1]


def rule_fan_out(grid: pd.DataFrame, ports_thresh: int = 30, hosts_thresh: int = 20) -> list[Detection]:
    out = []
    for r in grid.itertuples():
        if r.uniq_dst_ports >= ports_thresh or r.uniq_dst_hosts >= hosts_thresh:
            out.append(Detection(r.host, int(r.bin), "fan_out", float(max(r.uniq_dst_ports, r.uniq_dst_hosts)),
                                 f"{r.uniq_dst_ports} dst ports, {r.uniq_dst_hosts} dst hosts in one bin"))
    return out


def rule_byte_spike(grid: pd.DataFrame, factor: float = 10.0, min_bytes: int = 1_000_000) -> list[Detection]:
    out = []
    med = grid.groupby("host")["bytes"].median()
    for r in grid.itertuples():
        base = max(float(med[r.host]), 1.0)
        if r.bytes > min_bytes and r.bytes > factor * base:
            out.append(Detection(r.host, int(r.bin), "byte_spike", r.bytes / base,
                                 f"{r.bytes:,} bytes = {r.bytes / base:.0f}x host median"))
    return out


def rule_beaconing(flows: pd.DataFrame, min_events: int = 10, max_cv: float = 0.1,
                   min_interval: float = 5.0, bin_s: int = BIN_S) -> list[Detection]:
    """Flag (src, dst, port) triples whose inter-arrival times are very regular (coefficient of variation < max_cv)."""
    out = []
    for (src, dst, port), g in flows.groupby(["src", "dst", "dst_port"]):
        if len(g) < min_events:
            continue
        ts = np.sort(g["ts"].to_numpy())
        gaps = np.diff(ts)
        mean = gaps.mean()
        if mean < min_interval:
            continue
        cv = gaps.std() / mean
        if cv < max_cv:
            for b in range(int(ts[0] // bin_s), int(ts[-1] // bin_s) + 1):
                out.append(Detection(str(src), b, "beaconing", float(1 - cv),
                                     f"{dst}:{port} every {mean:.1f}s (CV {cv:.3f}, {len(g)} flows)"))
    return out


def detect_all(flows: pd.DataFrame, seed: int = 0, bin_s: int = BIN_S):
    grid = build_features(flows, bin_s)
    dets = (zscore_detect(grid) + iforest_detect(grid, seed=seed) + rule_fan_out(grid)
            + rule_byte_spike(grid) + rule_beaconing(flows, bin_s=bin_s))
    return grid, dets


def truth_bins(labels: list[dict], bin_s: int = BIN_S) -> set[tuple[str, int]]:
    return {(l["host"], b) for l in labels for b in range(int(l["start"] // bin_s), int(l["end"] // bin_s) + 1)}


def _prf(pred: set, truth: set) -> dict:
    tp, fp, fn = len(pred & truth), len(pred - truth), len(truth - pred)
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": p, "recall": r, "f1": 2 * p * r / (p + r) if p + r else 0.0}


def evaluate(detections: list[Detection], labels: list[dict], bin_s: int = BIN_S) -> dict:
    """Precision/recall at host-bin level for each method, rules combined, and all combined.

    'events_detected' counts injected anomalies hit by at least one detection of that group in a bin they overlap.
    """
    truth = truth_bins(labels, bin_s)
    groups = {m: {m} for m in ("zscore", "iforest", *RULE_METHODS)}
    groups["rules (combined)"] = set(RULE_METHODS)
    groups["all (combined)"] = {"zscore", "iforest", *RULE_METHODS}
    res = {}
    for name, methods in groups.items():
        pred = {(d.host, d.bin) for d in detections if d.method in methods}
        row = _prf(pred, truth)
        hit = sum(1 for l in labels if any(
            (l["host"], b) in pred for b in range(int(l["start"] // bin_s), int(l["end"] // bin_s) + 1)))
        row["events_detected"] = f"{hit}/{len(labels)}"
        res[name] = row
    return res
