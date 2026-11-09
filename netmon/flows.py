"""NetFlow-like flow records: CSV ingest and a SYNTHETIC generator with labelled injected anomalies."""

from __future__ import annotations

import numpy as np
import pandas as pd

COLUMNS = ["ts", "src", "dst", "dst_port", "proto", "bytes", "packets"]
EPOCH0 = 1_767_225_600  # 2026-01-01 00:00:00 UTC; all synthetic data is placed relative to this


def load_csv(path: str) -> pd.DataFrame:
    """Read flows from CSV with columns ts (epoch seconds or ISO-8601), src, dst, dst_port, proto, bytes, packets."""
    df = pd.read_csv(path)
    missing = [c for c in COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"flow CSV is missing columns: {missing}")
    df = df[COLUMNS].copy()
    if not pd.api.types.is_numeric_dtype(df["ts"]):
        df["ts"] = (pd.to_datetime(df["ts"], utc=True) - pd.Timestamp("1970-01-01", tz="UTC")).dt.total_seconds()
    for c in ("dst_port", "bytes", "packets"):
        df[c] = pd.to_numeric(df[c], errors="raise")
    if (df["bytes"] < 0).any() or (df["packets"] < 0).any():
        raise ValueError("bytes and packets must be non-negative")
    return df.sort_values("ts").reset_index(drop=True)


def write_csv(df: pd.DataFrame, path: str) -> None:
    df[COLUMNS].to_csv(path, index=False)


def _frame(ts, src, dst, port, nbytes, npk, proto="tcp") -> pd.DataFrame:
    n = len(ts)
    return pd.DataFrame({"ts": ts, "src": src, "dst": dst, "dst_port": port, "proto": proto,
                         "bytes": np.broadcast_to(nbytes, n).astype(int), "packets": np.broadcast_to(npk, n).astype(int)})


def generate_synthetic(seed: int = 7, hours: float = 8.0, n_hosts: int = 15, inject: bool = True):
    """Return (flows, labels). ALL DATA IS SYNTHETIC.

    Normal traffic: per-host Poisson flow arrivals to a few fixed servers (TEST-NET-3 addresses), log-normal sizes.
    Injected (labelled): port scan, fan-out sweep, beaconing, and two byte spikes (needs hours >= 7).
    """
    rng = np.random.default_rng(seed)
    n_min = int(hours * 60)
    hosts = [f"10.0.0.{10 + i}" for i in range(n_hosts)]
    servers = [f"203.0.113.{i}" for i in range(1, 21)]
    ports = np.array([443, 80, 53, 22, 993, 123, 8080])
    pw = np.array([0.55, 0.15, 0.12, 0.03, 0.05, 0.05, 0.05])
    parts = []
    for h in hosts:
        lam = rng.uniform(1.5, 6.0)
        dsts = rng.choice(servers, 4, replace=False)
        counts = rng.poisson(lam, n_min)
        total = int(counts.sum())
        ts = EPOCH0 + np.repeat(np.arange(n_min), counts) * 60 + rng.uniform(0, 60, total)
        nb = np.minimum(rng.lognormal(np.log(6000), 1.2, total), 5e6).astype(int) + 40
        npk = np.maximum(1, nb // 900 + rng.poisson(2, total))
        port = rng.choice(ports, total, p=pw)
        f = _frame(ts, h, rng.choice(dsts, total), port, nb, npk)
        f.loc[f["dst_port"].isin([53, 123]), "proto"] = "udp"
        parts.append(f)
    labels: list[dict] = []
    if inject:
        if hours < 7:
            raise ValueError("inject=True needs hours >= 7")
        a, b, c, d, e = rng.choice(hosts, 5, replace=False)
        H = 3600

        def label(kind, host, start, end):
            labels.append({"kind": kind, "host": str(host), "start": float(start), "end": float(end)})

        # 1. port scan: one target, 150 distinct ports, tiny flows, 4 minutes
        s = EPOCH0 + 2 * H
        ts = s + np.sort(rng.uniform(0, 240, 150))
        parts.append(_frame(ts, a, "10.0.0.200", np.arange(1000, 1150), 60, 1))
        label("port_scan", a, s, s + 240)
        # 2. fan-out sweep: 40 distinct hosts on port 445, 4 minutes
        s = EPOCH0 + 5 * H
        ts = s + np.sort(rng.uniform(0, 240, 40))
        parts.append(_frame(ts, b, [f"10.0.1.{i}" for i in range(1, 41)], 445, 60, 1))
        label("fan_out", b, s, s + 240)
        # 3. beaconing: fixed destination every 60 s (+/- 0.5 s) for 90 minutes, tiny payload
        s = EPOCH0 + 3 * H
        ts = s + np.arange(90) * 60 + rng.uniform(-0.5, 0.5, 90)
        parts.append(_frame(ts, c, "198.51.100.77", 8443, 300, 3))
        label("beaconing", c, s, s + 90 * 60)
        # 4/5. byte spikes: 60 flows of 5-20 MB (d) and 40 flows (e) within a few minutes
        for host, start_h, n_fl, dur in ((d, 6.0, 60, 300), (e, 1.0, 40, 180)):
            s = EPOCH0 + start_h * H
            ts = s + np.sort(rng.uniform(0, dur, n_fl))
            parts.append(_frame(ts, host, "198.51.100.9", 443, rng.integers(5_000_000, 20_000_000, n_fl), 9000))
            label("byte_spike", host, s, s + dur)
    flows = pd.concat(parts, ignore_index=True).sort_values("ts").reset_index(drop=True)
    return flows, labels
