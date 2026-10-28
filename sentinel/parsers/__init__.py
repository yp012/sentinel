"""Log parsers. Each module exposes ``parse_line(line) -> Event | None``."""

from __future__ import annotations

import re
from typing import Callable, Optional

from sentinel.models import Event
from sentinel.parsers import nginx, pacs, ssh, vpn

PARSERS: dict[str, Callable[[str], Optional[Event]]] = {
    "ssh": ssh.parse_line,
    "nginx": nginx.parse_line,
    "vpn": vpn.parse_line,
    "pacs": pacs.parse_line,
}

_NGINX_HINT = re.compile(r'^\S+ \S+ \S+ \[[^\]]+\] "')
_SSH_HINT = re.compile(r"\ssshd(?:-session)?(?:\[\d+\])?:\s")


def detect_format(line: str) -> Optional[str]:
    """Cheap sniff of which parser a line belongs to. None if nothing fits."""
    text = line.strip()
    if not text:
        return None
    if text.startswith("{"):
        return "vpn"
    if _NGINX_HINT.match(text):
        return "nginx"
    if _SSH_HINT.search(text):
        return "ssh"
    if text.count(",") >= len(pacs.COLUMNS) - 1:
        return "pacs"
    return None


def parse_any(line: str) -> Optional[Event]:
    """Route a raw line to the matching parser. Never raises."""
    try:
        fmt = detect_format(line)
    except Exception:
        return None
    if fmt is None:
        return None
    return PARSERS[fmt](line)


__all__ = ["PARSERS", "detect_format", "parse_any", "nginx", "pacs", "ssh", "vpn"]
