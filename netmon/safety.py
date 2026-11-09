"""Target validation. Scanning/monitoring is restricted to loopback and RFC1918 addresses by default."""

from __future__ import annotations

import ipaddress

NOTICE = (
    "SAFETY NOTICE: use this tool only on networks and devices you own or are explicitly "
    "authorised to test. Unauthorised scanning may be illegal."
)

MAX_HOSTS = 256
_ALLOWED = [ipaddress.ip_network(n) for n in ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


class TargetRefused(ValueError):
    """Raised when a target is not acceptable."""


def is_allowed_address(ip: ipaddress.IPv4Address) -> bool:
    return any(ip in net for net in _ALLOWED)


def resolve_targets(spec: str, i_own_this: bool = False) -> list[str]:
    """Turn 'localhost', an IPv4 address or a small IPv4 CIDR into a list of addresses.

    No DNS lookups are made: hostnames other than 'localhost' are refused. Public addresses
    are refused unless i_own_this is True.
    """
    spec = spec.strip()
    if spec.lower() == "localhost":
        return ["127.0.0.1"]
    try:
        net = ipaddress.ip_network(spec, strict=False)
    except ValueError:
        raise TargetRefused(f"{spec!r}: only IPv4 literals, CIDR ranges or 'localhost' are accepted (no DNS lookups)") from None
    if net.version != 4:
        raise TargetRefused("only IPv4 targets are supported")
    if net.num_addresses > MAX_HOSTS:
        raise TargetRefused(f"{spec}: range too large ({net.num_addresses} addresses, max {MAX_HOSTS})")
    hosts = list(net) if net.num_addresses <= 2 else list(net.hosts())
    if not i_own_this and not all(is_allowed_address(h) for h in hosts):
        raise TargetRefused(
            f"{spec}: public/non-RFC1918 addresses are refused. Pass --i-own-this only if you own or are authorised to test it."
        )
    return [str(h) for h in hosts]
