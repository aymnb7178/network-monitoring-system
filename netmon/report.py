"""Self-contained HTML dashboard (inline base64 PNGs, no scripts)."""

from __future__ import annotations

import base64
from html import escape

from netmon import charts
from netmon.monitor import compute_stats

CSS = """body{font-family:system-ui,sans-serif;margin:0;background:#f8fafc;color:#0f172a}
main{max-width:980px;margin:0 auto;padding:16px}h1{margin-bottom:4px}h2{margin-top:32px;border-bottom:1px solid #cbd5e1;padding-bottom:4px}
.note{background:#fef3c7;border:1px solid #f59e0b;padding:8px 12px;border-radius:6px;font-size:14px}
.cards{display:flex;flex-wrap:wrap;gap:12px}.card{background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:10px 16px;min-width:140px}
.card b{display:block;font-size:22px}table{border-collapse:collapse;width:100%;background:#fff;font-size:14px}
th,td{border:1px solid #e2e8f0;padding:4px 8px;text-align:right}th:first-child,td:first-child{text-align:left}
img{max-width:100%;height:auto;background:#fff;border:1px solid #e2e8f0}"""


def _img(png: bytes, alt: str) -> str:
    return f'<img alt="{escape(alt)}" src="data:image/png;base64,{base64.b64encode(png).decode()}">'


def _table(head: list[str], rows: list[list]) -> str:
    h = "".join(f"<th>{escape(str(c))}</th>" for c in head)
    b = "".join("<tr>" + "".join(f"<td>{escape(str(c))}</td>" for c in r) + "</tr>" for r in rows)
    return f"<table><tr>{h}</tr>{b}</table>"


def _f(v, fmt="{:.2f}"):
    return "-" if v is None else fmt.format(v)


def build_dashboard(checks, scans, flows, grid, detections, labels, evaluation) -> str:
    stats = compute_stats(checks)
    cards = [("Targets monitored", len(stats)), ("Checks stored", len(checks)), ("Synthetic flow records", f"{len(flows):,}"),
             ("Detections (all methods)", len(detections)), ("Injected anomalies", len(labels))]
    parts = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>",
        f"<title>netmon dashboard</title><style>{CSS}</style></head><body><main>",
        "<h1>netmon dashboard</h1>",
        "<p class='note'>Flow data below is <b>SYNTHETIC</b> (generated, with injected anomalies). Latency and open-port data come from "
        "local listeners on 127.0.0.1. Use this toolkit only on networks and devices you own or are authorised to test.</p>",
        "<div class='cards'>" + "".join(f"<div class='card'>{escape(str(k))}<b>{escape(str(v))}</b></div>" for k, v in cards) + "</div>",
        "<h2>Availability and latency</h2>", _img(charts.latency_chart(checks), "latency over time"),
        _table(["target", "samples", "failure rate", "mean ms", "p95 ms", "max ms", "jitter ms"],
               [[f"{s.host}:{s.port}", s.samples, f"{s.failure_rate:.0%}", _f(s.mean_ms, "{:.3f}"), _f(s.p95_ms, "{:.3f}"),
                 _f(s.max_ms, "{:.3f}"), _f(s.jitter_ms, "{:.3f}")] for s in stats]),
        "<h2>Open ports</h2>",
    ]
    rows = [[sr.host, r.port, r.state, r.banner or ""] for sr in scans for r in sr.open_ports]
    parts.append(_table(["host", "port", "state", "banner"], rows) if rows else "<p>No open ports found.</p>")
    parts += ["<h2>Top talkers</h2>", _img(charts.top_talkers_chart(flows), "top talkers"),
              "<h2>Anomaly timeline</h2>", _img(charts.anomaly_timeline_chart(grid, detections, labels), "anomaly timeline"),
              _table(["method", "TP", "FP", "FN", "precision", "recall", "F1", "events hit"],
                     [[m, e["tp"], e["fp"], e["fn"], f"{e['precision']:.2f}", f"{e['recall']:.2f}", f"{e['f1']:.2f}", e["events_detected"]]
                      for m, e in evaluation.items()]),
              "<p>Precision/recall are computed per (host, 5-minute bin) against anomalies injected into synthetic data; "
              "they say nothing about real traffic.</p></main></body></html>"]
    return "".join(parts)
