import socket
import time

import pytest

from netmon import scanner
from netmon.cli import main
from netmon.safety import TargetRefused, resolve_targets


def test_localhost_and_private_allowed():
    assert resolve_targets("localhost") == ["127.0.0.1"]
    assert resolve_targets("192.168.1.5") == ["192.168.1.5"]
    assert len(resolve_targets("10.0.0.0/30")) == 2


def test_public_refused_unless_flag():
    with pytest.raises(TargetRefused):
        resolve_targets("8.8.8.8")
    assert resolve_targets("8.8.8.8", i_own_this=True) == ["8.8.8.8"]


def test_hostnames_and_big_ranges_refused():
    with pytest.raises(TargetRefused):
        resolve_targets("example.com")
    with pytest.raises(TargetRefused):
        resolve_targets("10.0.0.0/16", i_own_this=True)


def test_mixed_range_refused():
    with pytest.raises(TargetRefused):
        resolve_targets("172.15.255.254/30")  # straddles the end of public space below 172.16/12


def test_parse_ports():
    assert scanner.parse_ports("22,80,8000-8002") == [22, 80, 8000, 8001, 8002]
    assert scanner.parse_ports("common") == scanner.COMMON_PORTS
    with pytest.raises(ValueError):
        scanner.parse_ports("0-5")
    with pytest.raises(ValueError):
        scanner.parse_ports("1-5000")


def test_scan_finds_open_and_closed(listener, closed_port):
    port = listener.getsockname()[1]
    res = scanner.scan_host("127.0.0.1", [port, closed_port], timeout=0.5)
    states = {r.port: r.state for r in res.results}
    assert states[port] == "open" and states[closed_port] == "closed"
    assert [p.port for p in res.open_ports] == [port]


def test_banner_off_by_default_and_on_when_asked():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    port = srv.getsockname()[1]
    import threading

    conns = []

    def serve():
        for _ in range(2):
            c, _ = srv.accept()
            c.sendall(b"HELLO-TEST 1.0\r\n")
            conns.append(c)
    threading.Thread(target=serve, daemon=True).start()
    assert scanner.scan_host("127.0.0.1", [port]).open_ports[0].banner is None
    assert "HELLO-TEST" in scanner.scan_host("127.0.0.1", [port], banner=True).open_ports[0].banner
    srv.close()


def test_rate_limiter_spaces_calls():
    rl = scanner.RateLimiter(50)  # 20 ms apart
    t0 = time.monotonic()
    for _ in range(6):
        rl.wait()
    assert time.monotonic() - t0 >= 5 * 0.02 * 0.9


def test_cli_refuses_public_scan(capsys):
    assert main(["scan", "8.8.8.8"]) == 2
    assert "refused" in capsys.readouterr().err


def test_cli_help_has_safety_notice(capsys):
    with pytest.raises(SystemExit):
        main(["scan", "--help"])
    assert "authorised" in capsys.readouterr().out
