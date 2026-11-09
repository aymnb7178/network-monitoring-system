"""TCP-connect availability and latency monitor with SQLite storage."""

from __future__ import annotations

import logging
import socket
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import asdict, dataclass
from typing import Callable, Iterable

import numpy as np
import pandas as pd

log = logging.getLogger("netmon.monitor")
MAX_WORKERS = 64


@dataclass(frozen=True)
class CheckResult:
    ts: float
    host: str
    port: int
    ok: bool
    latency_ms: float | None
    error: str | None


@dataclass(frozen=True)
class TargetStats:
    host: str
    port: int
    samples: int
    failures: int
    failure_rate: float
    mean_ms: float | None
    p95_ms: float | None
    max_ms: float | None
    jitter_ms: float | None  # mean absolute difference of consecutive successful latencies


def tcp_check(host: str, port: int, timeout: float = 1.0) -> CheckResult:
    ts = time.time()
    t0 = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
        return CheckResult(ts, host, port, True, (time.perf_counter() - t0) * 1000.0, None)
    except OSError as exc:
        return CheckResult(ts, host, port, False, None, type(exc).__name__)


def run_round(targets: list[tuple[str, int]], timeout: float = 1.0, max_workers: int = 16) -> list[CheckResult]:
    """Check all targets once, concurrently (workers bounded by MAX_WORKERS)."""
    if not targets:
        return []
    workers = max(1, min(max_workers, MAX_WORKERS, len(targets)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(lambda t: tcp_check(t[0], t[1], timeout), targets))


def run_monitor(
    targets: list[tuple[str, int]],
    count: int = 10,
    interval: float = 1.0,
    timeout: float = 1.0,
    max_workers: int = 16,
    store: "Store | None" = None,
    on_round: Callable[[int, list[CheckResult]], None] | None = None,
) -> list[CheckResult]:
    all_results: list[CheckResult] = []
    for i in range(count):
        t0 = time.monotonic()
        res = run_round(targets, timeout, max_workers)
        all_results.extend(res)
        if store:
            store.save(res)
        if on_round:
            on_round(i, res)
        log.debug("round %d: %d/%d ok", i, sum(r.ok for r in res), len(res))
        if i < count - 1:
            time.sleep(max(0.0, interval - (time.monotonic() - t0)))
    return all_results


def parse_target(text: str) -> tuple[str, int]:
    host, sep, port = text.rpartition(":")
    if not sep or not host or not port.isdigit() or not (1 <= int(port) <= 65535):
        raise ValueError(f"target must look like host:port, got {text!r}")
    return host, int(port)


def to_frame(results: Iterable[CheckResult]) -> pd.DataFrame:
    return pd.DataFrame([asdict(r) for r in results], columns=["ts", "host", "port", "ok", "latency_ms", "error"])


def compute_stats(results: Iterable[CheckResult] | pd.DataFrame) -> list[TargetStats]:
    df = results if isinstance(results, pd.DataFrame) else to_frame(results)
    out: list[TargetStats] = []
    if df.empty:
        return out
    for (host, port), g in df.sort_values("ts").groupby(["host", "port"], sort=True):
        lat = g.loc[g["ok"].astype(bool), "latency_ms"].astype(float).to_numpy()
        n = len(g)
        fails = int((~g["ok"].astype(bool)).sum())
        out.append(
            TargetStats(
                host=str(host), port=int(port), samples=n, failures=fails, failure_rate=fails / n,
                mean_ms=float(lat.mean()) if len(lat) else None,
                p95_ms=float(np.percentile(lat, 95)) if len(lat) else None,
                max_ms=float(lat.max()) if len(lat) else None,
                jitter_ms=float(np.abs(np.diff(lat)).mean()) if len(lat) > 1 else None,
            )
        )
    return out


class Store:
    """SQLite persistence for check results."""

    def __init__(self, path: str):
        self.path = path
        with closing(sqlite3.connect(path)) as c:
            c.execute(
                "CREATE TABLE IF NOT EXISTS checks (id INTEGER PRIMARY KEY, ts REAL NOT NULL, host TEXT NOT NULL,"
                " port INTEGER NOT NULL, ok INTEGER NOT NULL, latency_ms REAL, error TEXT)"
            )
            c.commit()

    def save(self, results: Iterable[CheckResult]) -> None:
        rows = [(r.ts, r.host, r.port, int(r.ok), r.latency_ms, r.error) for r in results]
        with closing(sqlite3.connect(self.path)) as c:
            c.executemany("INSERT INTO checks (ts, host, port, ok, latency_ms, error) VALUES (?,?,?,?,?,?)", rows)
            c.commit()

    def load(self) -> pd.DataFrame:
        with closing(sqlite3.connect(self.path)) as c:
            df = pd.read_sql_query("SELECT ts, host, port, ok, latency_ms, error FROM checks ORDER BY ts, id", c)
        df["ok"] = df["ok"].astype(bool)
        return df
