"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from dataclasses import asdict

from netmon import __version__, anomaly, flows as flowmod, inventory, monitor, scanner
from netmon.alerts import (AlertEngine, ConsoleSink, JsonlSink, alerts_from_detections, alerts_from_stats)
from netmon.safety import NOTICE, TargetRefused, resolve_targets

log = logging.getLogger("netmon")


def _stats_table(stats) -> str:
    f = lambda v: "-" if v is None else f"{v:.3f}"
    lines = [f"{'target':<22}{'n':>4}{'fail%':>7}{'mean ms':>9}{'p95 ms':>9}{'jitter ms':>11}"]
    for s in stats:
        lines.append(f"{s.host + ':' + str(s.port):<22}{s.samples:>4}{s.failure_rate * 100:>7.0f}{f(s.mean_ms):>9}{f(s.p95_ms):>9}{f(s.jitter_ms):>11}")
    return "\n".join(lines)


def _eval_table(ev: dict) -> str:
    lines = [f"{'method':<18}{'TP':>4}{'FP':>5}{'FN':>5}{'prec':>7}{'recall':>8}{'F1':>6}  events"]
    for m, e in ev.items():
        lines.append(f"{m:<18}{e['tp']:>4}{e['fp']:>5}{e['fn']:>5}{e['precision']:>7.2f}{e['recall']:>8.2f}{e['f1']:>6.2f}  {e['events_detected']}")
    return "\n".join(lines)


def _sinks(path):
    return [ConsoleSink()] + ([JsonlSink(path)] if path else [])


def cmd_monitor(a) -> int:
    try:
        targets = []
        for t in a.target:
            host, port = monitor.parse_target(t)
            targets.append((resolve_targets(host, a.i_own_this)[0], port))
    except (ValueError, TargetRefused) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    store = monitor.Store(a.db) if a.db else None
    res = monitor.run_monitor(targets, a.count, a.interval, a.timeout, a.workers, store)
    stats = monitor.compute_stats(res)
    print(_stats_table(stats))
    AlertEngine(_sinks(a.alerts_jsonl)).process(alerts_from_stats(stats, time.time()))
    return 0


def cmd_scan(a) -> int:
    try:
        hosts = resolve_targets(a.target, a.i_own_this)
        ports = scanner.parse_ports(a.ports)
    except (ValueError, TargetRefused) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    results = [scanner.scan_host(h, ports, a.timeout, a.workers, a.rate, a.banner) for h in hosts]
    for r in results:
        print(f"{r.host}: scanned {r.ports_scanned} ports in {r.seconds:.2f}s, {len(r.open_ports)} open")
        for p in r.open_ports:
            print(f"  {p.port}/tcp open" + (f"  {p.banner}" if p.banner else ""))
    if a.json_out:
        with open(a.json_out, "w", encoding="utf-8") as fh:
            json.dump([{"host": r.host, "open": [asdict(p) for p in r.open_ports]} for r in results], fh, indent=2)
    return 0


def cmd_inventory(a) -> int:
    devices = inventory.dedupe(inventory.parse_auto(open(a.file).read())) if a.file else inventory.read_local_table()
    if not devices:
        print("no neighbour entries found")
    for d in devices:
        print(f"{d.ip:<16}{d.mac:<19}{d.iface or '-':<10}{d.state or '-':<11}{d.vendor}")
    return 0


def _load_flows(a):
    if getattr(a, "csv", None):
        return flowmod.load_csv(a.csv), None
    return flowmod.generate_synthetic(seed=a.seed)


def cmd_flows(a) -> int:
    if a.flows_cmd == "generate":
        df, labels = flowmod.generate_synthetic(seed=a.seed)
        flowmod.write_csv(df, a.out)
        if a.labels:
            with open(a.labels, "w", encoding="utf-8") as fh:
                json.dump(labels, fh, indent=2)
        print(f"wrote {len(df):,} SYNTHETIC flow records to {a.out}")
        return 0
    df, labels = _load_flows(a)
    if a.labels:
        labels = json.load(open(a.labels))
    grid, dets = anomaly.detect_all(df, seed=a.seed)
    print(f"{len(df):,} flows, {len(grid):,} host-bins, {len(dets)} detections")
    if labels:
        print(_eval_table(anomaly.evaluate(dets, labels)))
        print("(precision/recall are against SYNTHETIC injected anomalies only)")
    eng = AlertEngine(_sinks(a.alerts_jsonl), cooldown_s=900, min_severity="warning")
    eng.process(alerts_from_detections(dets))
    print(f"alerts emitted: {len(eng.emitted)}, suppressed by cooldown: {eng.suppressed}")
    return 0


def cmd_dashboard(a) -> int:
    from netmon.report import build_dashboard
    df, labels = flowmod.generate_synthetic(seed=a.seed)
    grid, dets = anomaly.detect_all(df, seed=a.seed)
    checks = monitor.Store(a.db).load()
    scans = []
    if a.scan_json:
        for item in json.load(open(a.scan_json)):
            scans.append(scanner.ScanResult(item["host"], 0, [scanner.PortResult(**p) for p in item["open"]]))
    html = build_dashboard(checks, scans, df, grid, dets, labels, anomaly.evaluate(dets, labels))
    with open(a.out, "w", encoding="utf-8") as fh:
        fh.write(html)
    print(f"wrote {a.out}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="netmon", description="Defensive network monitoring toolkit.\n\n" + NOTICE,
                                epilog=NOTICE, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=__version__)
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)
    own = dict(action="store_true", help="allow non-private targets; only if you own or are authorised to test them")

    m = sub.add_parser("monitor", help="TCP connect availability/latency checks", epilog=NOTICE)
    m.add_argument("target", nargs="+", help="host:port (IPv4 or localhost)")
    m.add_argument("--count", type=int, default=10)
    m.add_argument("--interval", type=float, default=1.0)
    m.add_argument("--timeout", type=float, default=1.0)
    m.add_argument("--workers", type=int, default=16)
    m.add_argument("--db", help="SQLite file to store results")
    m.add_argument("--alerts-jsonl")
    m.add_argument("--i-own-this", **own)
    m.set_defaults(fn=cmd_monitor)

    s = sub.add_parser("scan", help="TCP connect port scan (localhost/RFC1918 only by default)", epilog=NOTICE)
    s.add_argument("target", help="localhost, an IPv4 address or a CIDR of at most 256 addresses")
    s.add_argument("--ports", default="common", help="'common' or e.g. 22,80,8000-8100 (max 4096 ports)")
    s.add_argument("--timeout", type=float, default=0.5)
    s.add_argument("--workers", type=int, default=32, help="max 64")
    s.add_argument("--rate", type=float, default=scanner.DEFAULT_RATE, help="max connection attempts per second")
    s.add_argument("--banner", action="store_true", help="read a passive banner from open ports (off by default)")
    s.add_argument("--json-out")
    s.add_argument("--i-own-this", **own)
    s.set_defaults(fn=cmd_scan)

    i = sub.add_parser("inventory", help="list devices from the OS neighbour/ARP table")
    i.add_argument("--file", help="parse saved `ip neigh`, `arp -a` or /proc/net/arp text instead of the live table")
    i.set_defaults(fn=cmd_inventory)

    f = sub.add_parser("flows", help="flow analysis (synthetic generator or CSV)")
    fs = f.add_subparsers(dest="flows_cmd", required=True)
    g = fs.add_parser("generate", help="write a SYNTHETIC flow CSV")
    g.add_argument("--out", required=True)
    g.add_argument("--labels", help="also write ground-truth labels JSON")
    g.add_argument("--seed", type=int, default=7)
    an = fs.add_parser("analyze", help="detect anomalies in a CSV, or in fresh synthetic data if --csv is omitted")
    an.add_argument("--csv")
    an.add_argument("--labels", help="ground-truth labels JSON (enables precision/recall)")
    an.add_argument("--seed", type=int, default=7)
    an.add_argument("--alerts-jsonl")
    f.set_defaults(fn=cmd_flows)

    d = sub.add_parser("dashboard", help="write the HTML dashboard (flow data is SYNTHETIC)")
    d.add_argument("--db", required=True, help="monitor SQLite file")
    d.add_argument("--scan-json")
    d.add_argument("--seed", type=int, default=7)
    d.add_argument("--out", default="dashboard.html")
    d.set_defaults(fn=cmd_dashboard)
    return p


def main(argv=None) -> int:
    a = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    return a.fn(a)
