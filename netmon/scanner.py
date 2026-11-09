"""TCP connect port scanner with bounded concurrency and a rate limit. Banner grab is off by default."""

from __future__ import annotations

import logging
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

log = logging.getLogger("netmon.scanner")

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723,
                3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 27017]
MAX_WORKERS = 64
MAX_PORTS = 4096
DEFAULT_RATE = 200.0  # connection attempts per second


@dataclass(frozen=True)
class PortResult:
    port: int
    state: str  # open | closed | filtered
    banner: str | None = None


@dataclass
class ScanResult:
    host: str
    ports_scanned: int
    results: list[PortResult] = field(default_factory=list)
    seconds: float = 0.0

    @property
    def open_ports(self) -> list[PortResult]:
        return sorted((r for r in self.results if r.state == "open"), key=lambda r: r.port)


class RateLimiter:
    """Spaces out call starts to at most `rate` per second (thread-safe)."""

    def __init__(self, rate: float):
        self.interval = 1.0 / rate if rate > 0 else 0.0
        self._next = 0.0
        self._lock = threading.Lock()

    def wait(self) -> None:
        if not self.interval:
            return
        with self._lock:
            now = time.monotonic()
            slot = max(now, self._next)
            self._next = slot + self.interval
        if slot > now:
            time.sleep(slot - now)


def parse_ports(spec: str) -> list[int]:
    """'common', or a list such as '22,80,8000-8100'. Capped at MAX_PORTS distinct ports."""
    if spec.strip().lower() == "common":
        return list(COMMON_PORTS)
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        lo, _, hi = part.partition("-")
        a, b = int(lo), int(hi or lo)
        if not (1 <= a <= b <= 65535):
            raise ValueError(f"invalid port range {part!r}")
        ports.update(range(a, b + 1))
        if len(ports) > MAX_PORTS:
            raise ValueError(f"too many ports (max {MAX_PORTS})")
    if not ports:
        raise ValueError("no ports given")
    return sorted(ports)


def _grab_banner(sock: socket.socket) -> str | None:
    """Passive: send nothing, just read whatever the service volunteers."""
    try:
        sock.settimeout(0.3)
        data = sock.recv(128)
    except OSError:
        return None
    text = "".join(ch if ch.isprintable() else " " for ch in data.decode("latin-1")).strip()
    return text or None


def scan_port(host: str, port: int, timeout: float, banner: bool, limiter: RateLimiter) -> PortResult:
    limiter.wait()
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            return PortResult(port, "open", _grab_banner(s) if banner else None)
    except ConnectionRefusedError:
        return PortResult(port, "closed")
    except OSError:
        return PortResult(port, "filtered")


def scan_host(host: str, ports: list[int], timeout: float = 0.5, workers: int = 32,
              rate: float = DEFAULT_RATE, banner: bool = False) -> ScanResult:
    workers = max(1, min(workers, MAX_WORKERS))
    limiter = RateLimiter(rate)
    t0 = time.monotonic()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(lambda p: scan_port(host, p, timeout, banner, limiter), ports))
    out = ScanResult(host=host, ports_scanned=len(ports), results=results, seconds=time.monotonic() - t0)
    log.info("scanned %s: %d ports, %d open, %.2fs", host, len(ports), len(out.open_ports), out.seconds)
    return out
