import pytest

from netmon import inventory
from netmon.monitor import CheckResult, Store, compute_stats, parse_target, run_round, tcp_check


def test_tcp_check_up_and_down(listener, closed_port):
    up = tcp_check("127.0.0.1", listener.getsockname()[1])
    assert up.ok and up.latency_ms > 0
    down = tcp_check("127.0.0.1", closed_port)
    assert not down.ok and down.error == "ConnectionRefusedError"


def test_run_round_concurrent(listener, closed_port):
    res = run_round([("127.0.0.1", listener.getsockname()[1]), ("127.0.0.1", closed_port)] * 3, max_workers=4)
    assert sum(r.ok for r in res) == 3 and len(res) == 6


def test_stats_jitter_and_failure_rate():
    lat = [1.0, 3.0, 2.0, None, 6.0]
    rs = [CheckResult(float(i), "h", 1, v is not None, v, None if v else "E") for i, v in enumerate(lat)]
    s = compute_stats(rs)[0]
    assert s.samples == 5 and s.failures == 1 and s.failure_rate == pytest.approx(0.2)
    assert s.mean_ms == pytest.approx(3.0)
    assert s.jitter_ms == pytest.approx((2 + 1 + 4) / 3)  # |3-1|, |2-3|, |6-2|


def test_store_roundtrip(tmp_path):
    st = Store(str(tmp_path / "m.db"))
    st.save([CheckResult(1.0, "127.0.0.1", 80, True, 0.5, None), CheckResult(2.0, "127.0.0.1", 80, False, None, "TimeoutError")])
    df = st.load()
    assert list(df["ok"]) == [True, False] and df["error"].iloc[1] == "TimeoutError"


def test_parse_target():
    assert parse_target("127.0.0.1:80") == ("127.0.0.1", 80)
    with pytest.raises(ValueError):
        parse_target("nonsense")


IP_NEIGH = """192.168.1.1 dev eth0 lladdr b8:27:eb:12:34:56 REACHABLE
192.168.1.9 dev eth0  FAILED
192.168.1.20 dev eth0 lladdr 00:50:56:aa:bb:cc STALE
fe80::1 dev eth0 lladdr 52:54:00:00:00:01 router STALE
"""
ARP_A = """? (192.168.1.1) at b8:27:eb:12:34:56 [ether] on eth0
? (192.168.1.50) at <incomplete> on eth0
router.lan (192.168.1.2) at 0:50:56:1:2:3 on en0 ifscope [ethernet]
"""
ARP_WIN = """Interface: 192.168.1.5 --- 0x4
  Internet Address      Physical Address      Type
  192.168.1.1           b8-27-eb-12-34-56     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
"""
PROC = """IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         b8:27:eb:12:34:56     *        eth0
192.168.1.7      0x1         0x0         00:00:00:00:00:00     *        eth0
"""


def test_parse_ip_neigh():
    d = inventory.parse_ip_neigh(IP_NEIGH)
    assert [x.ip for x in d] == ["192.168.1.1", "192.168.1.20", "fe80::1"]
    assert d[0].mac == "B8:27:EB:12:34:56" and d[0].state == "REACHABLE" and d[0].vendor == "Raspberry Pi Foundation"


def test_parse_arp_a_unix_and_windows():
    d = inventory.parse_arp_a(ARP_A)
    assert [x.ip for x in d] == ["192.168.1.1", "192.168.1.2"]
    assert d[1].mac == "00:50:56:01:02:03" and d[1].vendor == "VMware" and d[1].iface == "en0"
    w = inventory.parse_arp_a(ARP_WIN)
    assert w[0].ip == "192.168.1.1" and w[0].state == "dynamic"


def test_parse_proc_net_arp_skips_incomplete():
    d = inventory.parse_proc_net_arp(PROC)
    assert len(d) == 1 and d[0].iface == "eth0"


def test_detect_format_and_oui():
    assert inventory.detect_format(PROC) == "proc"
    assert inventory.detect_format(IP_NEIGH) == "ip-neigh"
    assert inventory.detect_format(ARP_A) == "arp-a"
    assert inventory.oui_lookup("de:ad:be:ef:00:01").startswith("locally administered")
    assert inventory.oui_lookup("00:11:22:33:44:55") == "unknown"
    assert inventory.oui_lookup("garbage") == "unknown"
