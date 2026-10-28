"""IP classification helpers shared by intel and SOAR.

``ipaddress``'s ``is_private`` also covers the RFC 5737 documentation ranges, which
the simulator uses as attacker IPs, so the ranges are listed explicitly here.
"""

from __future__ import annotations

import ipaddress
from typing import Iterable, Union

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

PRIVATE_NETWORKS: tuple[IPNetwork, ...] = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",  # RFC 1918
    "100.64.0.0/10",                                  # RFC 6598 carrier-grade NAT
    "fc00::/7",                                       # IPv6 unique local
))


def parse_ip(value: str) -> IPAddress:
    """Strict parse. Raises ValueError for anything that is not a bare IP address."""
    if not isinstance(value, str) or value != value.strip():
        raise ValueError(f"not an IP address: {value!r}")
    return ipaddress.ip_address(value)


def parse_networks(values: Iterable[str]) -> tuple[IPNetwork, ...]:
    return tuple(ipaddress.ip_network(v, strict=False) for v in values)


def is_private_or_special(addr: IPAddress) -> bool:
    """RFC 1918 / ULA / CGNAT, loopback, link-local, multicast, unspecified, reserved."""
    if getattr(addr, "ipv4_mapped", None) is not None:
        addr = addr.ipv4_mapped
    return (
        addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_unspecified
        or addr.is_reserved
        or any(addr in net for net in PRIVATE_NETWORKS if net.version == addr.version)
    )
