"""VPN gateway JSON-lines parser.

Expected shape: ``{"ts": ..., "user": ..., "src_ip": ..., "event": "vpn_login",
"success": true}``. Any extra keys (e.g. geo data) are kept in ``fields``.
"""

from __future__ import annotations

import json
from typing import Optional

from sentinel.models import Event
from sentinel.parsers._common import is_ip, parse_iso_ts

_REQUIRED = ("ts", "user", "src_ip", "event", "success")


def parse_line(line: str) -> Optional[Event]:
    try:
        return _parse(line)
    except Exception:  # parsers must never raise on bad input
        return None


def _parse(line: str) -> Optional[Event]:
    raw = line.rstrip("\r\n")
    try:
        doc = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(doc, dict) or any(k not in doc for k in _REQUIRED):
        return None
    if doc["event"] != "vpn_login" or not isinstance(doc["success"], bool):
        return None
    user, ip = doc["user"], doc["src_ip"]
    if not isinstance(user, str) or not isinstance(ip, str) or not is_ip(ip):
        return None
    ts = parse_iso_ts(doc["ts"])
    if ts is None:
        return None

    fields = {k: v for k, v in doc.items() if k not in _REQUIRED}
    fields["success"] = doc["success"]
    return Event(
        ts=ts,
        source="vpn",
        event_type="vpn_login",
        src_ip=ip,
        user=user,
        raw=raw,
        fields=fields,
    )
