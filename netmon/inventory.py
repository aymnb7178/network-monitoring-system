"""Device inventory from the OS neighbour/ARP table. Parsers are pure functions over text."""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

log = logging.getLogger("netmon.inventory")
_OUI_PATH = Path(__file__).parent / "data" / "oui.json"
_ZERO_MAC = "00:00:00:00:00:00"


@dataclass(frozen=True)
class Device:
    ip: str
    mac: str
    iface: str | None
    state: str | None
    vendor: str


def normalize_mac(raw: str) -> str | None:
    parts = re.split(r"[:-]", raw.strip())
    if len(parts) != 6 or not all(re.fullmatch(r"[0-9a-fA-F]{1,2}", p) for p in parts):
        return None
    return ":".join(p.zfill(2) for p in parts).upper()


@lru_cache(maxsize=1)
def _oui_table() -> dict[str, str]:
    return json.loads(_OUI_PATH.read_text(encoding="utf-8"))["prefixes"]


def oui_lookup(mac: str) -> str:
    """Vendor from the small bundled prefix list; 'unknown' otherwise."""
    m = normalize_mac(mac)
    if not m:
        return "unknown"
    if int(m[:2], 16) & 0x02:
        return "locally administered (randomised/virtual)"
    return _oui_table().get(m[:8], "unknown")


def _device(ip: str, mac_raw: str | None, iface: str | None, state: str | None) -> Device | None:
    mac = normalize_mac(mac_raw) if mac_raw else None
    if not mac or mac == _ZERO_MAC:
        return None
    return Device(ip, mac, iface, state, oui_lookup(mac))


_NEIGH = re.compile(r"^(?P<ip>\S+)\s+dev\s+(?P<iface>\S+)(?:\s+lladdr\s+(?P<mac>[0-9a-fA-F:]{17}))?.*?\b(?P<state>[A-Z]+)\s*$")


def parse_ip_neigh(text: str) -> list[Device]:
    """Parse `ip neigh` output. Entries without a lladdr (FAILED/INCOMPLETE) are skipped."""
    out = []
    for line in text.splitlines():
        m = _NEIGH.match(line.strip())
        if m:
            d = _device(m["ip"], m["mac"], m["iface"], m["state"])
            if d:
                out.append(d)
    return out


_ARP_UNIX = re.compile(r"^\S+\s+\((?P<ip>[\d.]+)\)\s+at\s+(?P<mac>\S+)(?:\s+\[\w+\])?(?:\s+on\s+(?P<iface>\S+))?")
_ARP_WIN = re.compile(r"^\s*(?P<ip>\d+\.\d+\.\d+\.\d+)\s+(?P<mac>[0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s+(?P<state>\w+)")


def parse_arp_a(text: str) -> list[Device]:
    """Parse `arp -a` output (Linux/macOS 'host (ip) at mac' style and Windows table style)."""
    out = []
    for line in text.splitlines():
        m = _ARP_UNIX.match(line.strip())
        if m:
            d = _device(m["ip"], m["mac"], m["iface"], None)
        else:
            m = _ARP_WIN.match(line)
            d = _device(m["ip"], m["mac"], None, m["state"]) if m else None
        if d:
            out.append(d)
    return out


def parse_proc_net_arp(text: str) -> list[Device]:
    """Parse /proc/net/arp. Rows with flags 0x0 (incomplete) or an all-zero MAC are skipped."""
    out = []
    for line in text.splitlines()[1:]:
        f = line.split()
        if len(f) >= 6 and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", f[0]):
            flags = int(f[2], 16) if f[2].startswith("0x") else 0
            if flags == 0:
                continue
            d = _device(f[0], f[3], f[5], "complete")
            if d:
                out.append(d)
    return out


def detect_format(text: str) -> str:
    first = next((ln for ln in text.splitlines() if ln.strip()), "")
    if first.startswith("IP address"):
        return "proc"
    if " dev " in text:
        return "ip-neigh"
    return "arp-a"


def parse_auto(text: str) -> list[Device]:
    return {"proc": parse_proc_net_arp, "ip-neigh": parse_ip_neigh, "arp-a": parse_arp_a}[detect_format(text)](text)


def dedupe(devices: list[Device]) -> list[Device]:
    seen: dict[tuple[str, str], Device] = {}
    for d in devices:
        seen.setdefault((d.ip, d.mac), d)
    return sorted(seen.values(), key=lambda d: tuple(int(p) for p in d.ip.split(".")) if re.fullmatch(r"[\d.]+", d.ip) else (999,))


def read_local_table() -> list[Device]:
    """Read the local neighbour table (read-only; no packets are sent). Returns [] if unavailable."""
    p = Path("/proc/net/arp")
    if p.exists():
        try:
            return dedupe(parse_proc_net_arp(p.read_text()))
        except OSError:
            pass
    for cmd, parser in ((["ip", "neigh"], parse_ip_neigh), (["arp", "-a"], parse_arp_a)):
        if shutil.which(cmd[0]):
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=5, check=False)
                return dedupe(parser(res.stdout))
            except (OSError, subprocess.SubprocessError):
                log.warning("failed to run %s", cmd)
    return []
