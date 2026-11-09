"""Demo: local listeners -> monitor + scan -> synthetic flows with injected anomalies -> dashboard + PNGs in docs/."""

import socket
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from netmon import anomaly, charts, flows, monitor, scanner  # noqa: E402
from netmon.alerts import AlertEngine, ConsoleSink, JsonlSink, alerts_from_detections, alerts_from_stats  # noqa: E402
from netmon.cli import _eval_table, _stats_table  # noqa: E402
from netmon.report import build_dashboard  # noqa: E402

OUT, DOCS = ROOT / "output", ROOT / "docs"


class Listener(threading.Thread):
    def __init__(self, port=0):
        super().__init__(daemon=True)
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.sock.bind(("127.0.0.1", port))
        except OSError:
            self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.start()

    def run(self):
        while True:
            try:
                c, _ = self.sock.accept()
                c.close()
            except OSError:
                return

    def stop(self):
        self.sock.close()


def main():
    OUT.mkdir(exist_ok=True)
    DOCS.mkdir(exist_ok=True)
    db = OUT / "monitor.db"
    db.unlink(missing_ok=True)
    (OUT / "alerts.jsonl").unlink(missing_ok=True)

    listeners = [Listener(p) for p in (18081, 18082, 18083, 18084)]
    flaky = listeners[3]
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    closed_port = probe.getsockname()[1]
    probe.close()  # nothing listens here
    targets = [("127.0.0.1", l.port) for l in listeners] + [("127.0.0.1", closed_port)]

    print("== Monitor: 5 local targets, 20 rounds (one listener stops after round 10, one port is closed)")
    store = monitor.Store(str(db))
    monitor.run_monitor(targets, count=20, interval=0.1, timeout=0.5, store=store,
                        on_round=lambda i, r: flaky.stop() if i == 9 else None)
    checks = store.load()
    stats = monitor.compute_stats(checks)
    print(_stats_table(stats))
    print("\n== Alerts from monitor stats")
    engine = AlertEngine([ConsoleSink(), JsonlSink(str(OUT / "alerts.jsonl"))], cooldown_s=900, min_severity="warning")
    engine.process(alerts_from_stats(stats, checks["ts"].max()))

    print("\n== Port scan of 127.0.0.1 (common preset + 18000-18100)")
    ports = sorted(set(scanner.COMMON_PORTS) | set(range(18000, 18101)))
    scan = scanner.scan_host("127.0.0.1", ports, timeout=0.3, rate=500)
    print(f"scanned {scan.ports_scanned} ports in {scan.seconds:.2f}s, open: {[p.port for p in scan.open_ports]}")

    print("\n== Flow analysis on SYNTHETIC flows with injected anomalies (seed 7)")
    df, labels = flows.generate_synthetic(seed=7)
    grid, dets = anomaly.detect_all(df, seed=7)
    ev = anomaly.evaluate(dets, labels)
    print(f"{len(df):,} flows, {len(grid):,} host-bins, {len(dets)} detections, {len(labels)} injected anomalies")
    print(_eval_table(ev))
    print("\n== Alerts from flow detections (warning and above, 15 min cooldown)")
    e2 = AlertEngine([ConsoleSink(), JsonlSink(str(OUT / "alerts.jsonl"))], cooldown_s=900, min_severity="warning")
    e2.process(alerts_from_detections(dets))
    print(f"alerts emitted: {len(e2.emitted)}, suppressed by cooldown: {e2.suppressed}")

    (DOCS / "latency.png").write_bytes(charts.latency_chart(checks))
    (DOCS / "top_talkers.png").write_bytes(charts.top_talkers_chart(df))
    (DOCS / "anomaly_timeline.png").write_bytes(charts.anomaly_timeline_chart(grid, dets, labels))
    (DOCS / "sample_dashboard.html").write_text(build_dashboard(checks, [scan], df, grid, dets, labels, ev), encoding="utf-8")
    print("\nWrote docs/sample_dashboard.html, docs/latency.png, docs/top_talkers.png, docs/anomaly_timeline.png")
    for l in listeners:
        l.stop()


if __name__ == "__main__":
    main()
