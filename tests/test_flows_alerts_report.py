import json

import numpy as np
import pandas as pd
import pytest

from netmon import anomaly
from netmon.alerts import (Alert, AlertEngine, JsonlSink, MockWebhookSink, alerts_from_detections, alerts_from_stats)
from netmon.cli import main
from netmon.flows import COLUMNS, generate_synthetic, load_csv, write_csv
from netmon.monitor import TargetStats
from netmon.report import build_dashboard


def test_generator_deterministic_and_labelled():
    a, la = generate_synthetic(seed=3)
    b, lb = generate_synthetic(seed=3)
    assert a.equals(b) and la == lb
    assert {l["kind"] for l in la} == {"port_scan", "fan_out", "beaconing", "byte_spike"}
    assert list(a.columns) == COLUMNS


def test_csv_roundtrip_and_validation(tmp_path):
    df, _ = generate_synthetic(seed=1, hours=7)
    p = tmp_path / "f.csv"
    write_csv(df, str(p))
    assert len(load_csv(str(p))) == len(df)
    (tmp_path / "bad.csv").write_text("ts,src\n1,2\n")
    with pytest.raises(ValueError):
        load_csv(str(tmp_path / "bad.csv"))


def test_iso_timestamps(tmp_path):
    p = tmp_path / "iso.csv"
    p.write_text("ts,src,dst,dst_port,proto,bytes,packets\n2026-01-01T00:00:00Z,10.0.0.1,1.2.3.4,443,tcp,100,1\n")
    assert load_csv(str(p))["ts"].iloc[0] == 1767225600


def _flows(rows):
    return pd.DataFrame(rows, columns=["ts", "src", "dst", "dst_port", "proto", "bytes", "packets"])


def test_beaconing_rule_regular_vs_random():
    rng = np.random.default_rng(0)
    reg = _flows([(i * 30.0, "h", "d", 443, "tcp", 100, 1) for i in range(30)])
    rnd = _flows([(t, "h", "d", 443, "tcp", 100, 1) for t in np.cumsum(rng.exponential(30, 30))])
    assert anomaly.rule_beaconing(reg)
    assert not anomaly.rule_beaconing(rnd)


def test_fan_out_and_byte_spike_rules():
    grid = pd.DataFrame({"host": ["a", "a", "a", "b"], "bin": [0, 1, 2, 0], "flows": 1, "bytes": [1000, 1000, 50_000_000, 1000],
                         "packets": 1, "uniq_dst_ports": [1, 40, 1, 1], "uniq_dst_hosts": [1, 1, 1, 1]})
    assert [(d.host, d.bin) for d in anomaly.rule_fan_out(grid)] == [("a", 1)]
    assert [(d.host, d.bin) for d in anomaly.rule_byte_spike(grid)] == [("a", 2)]


def test_features_fill_empty_bins():
    g = anomaly.build_features(_flows([(0, "a", "x", 1, "tcp", 10, 1), (1000, "a", "y", 2, "tcp", 20, 1)]))
    assert list(g["bin"]) == [0, 1, 2, 3] and g["bytes"].tolist() == [10, 0, 0, 20]


def test_evaluate_known_numbers():
    labels = [{"kind": "x", "host": "a", "start": 0, "end": 299}, {"kind": "x", "host": "b", "start": 300, "end": 599}]
    dets = [anomaly.Detection("a", 0, "fan_out", 1, ""), anomaly.Detection("c", 5, "fan_out", 1, "")]
    e = anomaly.evaluate(dets, labels)["fan_out"]
    assert (e["tp"], e["fp"], e["fn"]) == (1, 1, 1)
    assert e["precision"] == 0.5 and e["recall"] == 0.5 and e["events_detected"] == "1/2"


def test_end_to_end_synthetic_detection(synth):
    flows, labels, grid, dets = synth
    ev = anomaly.evaluate(dets, labels)
    assert ev["rules (combined)"]["precision"] == 1.0
    assert ev["rules (combined)"]["recall"] > 0.8
    assert ev["all (combined)"]["events_detected"] == "5/5"
    clean, _ = generate_synthetic(seed=7, inject=False)
    assert not anomaly.rule_beaconing(clean) and not anomaly.rule_fan_out(anomaly.build_features(clean))


def test_alert_cooldown_dedup_and_escalation():
    eng = AlertEngine([], cooldown_s=100)
    out = eng.process([Alert(0, "warning", "k", "s", "m"), Alert(50, "warning", "k", "s", "m"),
                       Alert(60, "critical", "k", "s", "m"), Alert(500, "warning", "k", "s", "m")])
    assert [a.ts for a in out] == [0, 60, 500] and eng.suppressed == 1


def test_alert_min_severity_and_sinks(tmp_path):
    hook, path = MockWebhookSink(), tmp_path / "a.jsonl"
    eng = AlertEngine([hook, JsonlSink(str(path))], min_severity="warning")
    eng.process([Alert(0, "info", "i", "s", "low"), Alert(1, "critical", "c", "s", "high")])
    assert len(hook.payloads) == 1 and json.loads(hook.payloads[0])["alert"]["kind"] == "c"
    lines = path.read_text().splitlines()
    assert len(lines) == 1 and json.loads(lines[0])["severity"] == "critical"


def test_alerts_from_stats():
    down = TargetStats("h", 1, 10, 10, 1.0, None, None, None, None)
    flaky = TargetStats("h", 2, 10, 3, 0.3, 1, 500.0, 600, 2)
    kinds = {a.kind for a in alerts_from_stats([down, flaky], 0.0)}
    assert kinds == {"target_down", "high_failure_rate", "high_latency"}


def test_dashboard_self_contained(synth, tmp_path):
    from netmon.monitor import CheckResult, to_frame
    flows, labels, grid, dets = synth
    checks = to_frame([CheckResult(float(i), "127.0.0.1", 80, i % 4 != 0, 0.5 if i % 4 else None, None) for i in range(8)])
    html = build_dashboard(checks, [], flows, grid, dets, labels, anomaly.evaluate(dets, labels))
    assert html.count("data:image/png;base64,") == 3 and "SYNTHETIC" in html and "<script" not in html
    assert "src=\"http" not in html


def test_cli_flows_analyze_and_generate(tmp_path, capsys):
    csv, lab = tmp_path / "f.csv", tmp_path / "l.json"
    assert main(["flows", "generate", "--out", str(csv), "--labels", str(lab)]) == 0
    assert main(["flows", "analyze", "--csv", str(csv), "--labels", str(lab), "--alerts-jsonl", str(tmp_path / "a.jsonl")]) == 0
    out = capsys.readouterr().out
    assert "rules (combined)" in out and "SYNTHETIC" in out
    assert (tmp_path / "a.jsonl").exists()


def test_cli_inventory_file(tmp_path, capsys):
    f = tmp_path / "arp.txt"
    f.write_text("192.168.1.1 dev eth0 lladdr b8:27:eb:12:34:56 REACHABLE\n")
    assert main(["inventory", "--file", str(f)]) == 0
    assert "Raspberry Pi" in capsys.readouterr().out
