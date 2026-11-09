"""Alert engine: severity, dedup/cooldown, and sinks (console, JSONL file, mock webhook)."""

from __future__ import annotations

import json
import sys
from dataclasses import asdict, dataclass, field
from typing import Protocol

from netmon.anomaly import BIN_S, Detection
from netmon.monitor import TargetStats

SEVERITIES = ("info", "warning", "critical")


@dataclass(frozen=True)
class Alert:
    ts: float
    severity: str
    kind: str
    subject: str
    message: str
    details: dict = field(default_factory=dict)


class Sink(Protocol):
    def emit(self, alert: Alert) -> None: ...


class ConsoleSink:
    def __init__(self, stream=None):
        self.stream = stream or sys.stdout

    def emit(self, alert: Alert) -> None:
        print(f"[{alert.severity.upper():8}] {alert.kind} {alert.subject}: {alert.message}", file=self.stream)


class JsonlSink:
    def __init__(self, path: str):
        self.path = path

    def emit(self, alert: Alert) -> None:
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(asdict(alert)) + "\n")


class MockWebhookSink:
    """Builds the JSON body a webhook would receive and keeps it in memory. It sends NOTHING over the network."""

    def __init__(self, url: str = "https://example.invalid/hook"):
        self.url = url
        self.payloads: list[str] = []

    def emit(self, alert: Alert) -> None:
        self.payloads.append(json.dumps({"text": f"[{alert.severity}] {alert.kind} {alert.subject}: {alert.message}",
                                         "alert": asdict(alert)}))


class AlertEngine:
    """Drops alerts below min_severity; suppresses repeats of (kind, subject) inside cooldown_s unless severity escalates."""

    def __init__(self, sinks: list[Sink], cooldown_s: float = 600.0, min_severity: str = "info"):
        self.sinks, self.cooldown_s = sinks, cooldown_s
        self.min_rank = SEVERITIES.index(min_severity)
        self._last: dict[tuple[str, str], tuple[float, int]] = {}
        self.emitted: list[Alert] = []
        self.suppressed = 0

    def process(self, alerts: list[Alert]) -> list[Alert]:
        out = []
        for a in sorted(alerts, key=lambda x: x.ts):
            rank = SEVERITIES.index(a.severity)
            if rank < self.min_rank:
                continue
            key = (a.kind, a.subject)
            prev = self._last.get(key)
            if prev and a.ts - prev[0] < self.cooldown_s and rank <= prev[1]:
                self.suppressed += 1
                continue
            self._last[key] = (a.ts, rank)
            for s in self.sinks:
                s.emit(a)
            out.append(a)
        self.emitted.extend(out)
        return out


def alerts_from_stats(stats: list[TargetStats], now: float, p95_ms: float = 200.0) -> list[Alert]:
    out = []
    for s in stats:
        subj = f"{s.host}:{s.port}"
        d = {"failure_rate": s.failure_rate, "samples": s.samples}
        if s.failure_rate >= 1.0:
            out.append(Alert(now, "critical", "target_down", subj, f"all {s.samples} checks failed", d))
        elif s.failure_rate >= 0.2:
            out.append(Alert(now, "warning", "high_failure_rate", subj,
                             f"{s.failures}/{s.samples} checks failed ({s.failure_rate:.0%})", d))
        if s.p95_ms is not None and s.p95_ms > p95_ms:
            out.append(Alert(now, "warning", "high_latency", subj, f"p95 {s.p95_ms:.1f} ms > {p95_ms:.0f} ms", d))
    return out


_SEV = {"beaconing": "critical", "fan_out": "warning", "byte_spike": "warning", "zscore": "info", "iforest": "info"}


def alerts_from_detections(dets: list[Detection], bin_s: int = BIN_S) -> list[Alert]:
    return [Alert(float(d.bin * bin_s), _SEV[d.method], d.method, d.host, d.detail, {"score": d.score}) for d in dets]
