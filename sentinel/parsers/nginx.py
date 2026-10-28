"""Nginx ``combined`` access log parser (``common`` format is accepted too)."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import unquote

from sentinel.models import Event
from sentinel.parsers._common import MONTHS, is_ip

# Quoted fields may contain backslash escapes (nginx writes " as \x22, but be lenient).
_Q = r'(?:[^"\\]|\\.)*'

_LINE = re.compile(
    r"^(?P<ip>\S+) \S+ (?P<ruser>\S+) \[(?P<time>[^\]]+)\] "
    rf'"(?P<request>{_Q})" (?P<status>\d{{3}}) (?P<bytes>\d+|-)'
    rf'(?: "(?P<referer>{_Q})" "(?P<ua>{_Q})")?'
    r"(?:\s.*)?$"
)
_TIME = re.compile(
    r"^(?P<day>\d{2})/(?P<mon>[A-Za-z]{3})/(?P<year>\d{4}):"
    r"(?P<h>\d{2}):(?P<m>\d{2}):(?P<s>\d{2}) (?P<sign>[+-])(?P<oh>\d{2})(?P<om>\d{2})$"
)
_REQUEST = re.compile(r"^(?P<method>[A-Z]+) (?P<uri>\S+)(?: (?P<proto>HTTP/[\d.]+))?$")

LOGIN_PATHS = frozenset({"/login", "/wp-login.php"})
MAX_DECODE_ROUNDS = 2


def _parse_time(text: str) -> Optional[datetime]:
    m = _TIME.match(text)
    if m is None:
        return None
    month = MONTHS.get(m.group("mon").lower())
    if month is None:
        return None
    offset = timedelta(hours=int(m.group("oh")), minutes=int(m.group("om")))
    if m.group("sign") == "-":
        offset = -offset
    try:
        local = datetime(
            int(m.group("year")), month, int(m.group("day")),
            int(m.group("h")), int(m.group("m")), int(m.group("s")),
            tzinfo=timezone(offset),
        )
    except ValueError:
        return None
    return local.astimezone(timezone.utc)


def decode_uri(uri: str, rounds: int = MAX_DECODE_ROUNDS) -> tuple[str, int]:
    """Percent-decode repeatedly (to unwrap double encoding). Returns (decoded, rounds)."""
    out = uri
    used = 0
    for _ in range(rounds):
        nxt = unquote(out, errors="replace")
        if nxt == out:
            break
        out = nxt
        used += 1
    return out, used


def parse_line(line: str) -> Optional[Event]:
    try:
        return _parse(line)
    except Exception:  # parsers must never raise on bad input
        return None


def _parse(line: str) -> Optional[Event]:
    raw = line.rstrip("\r\n")
    m = _LINE.match(raw)
    if m is None:
        return None
    ip = m.group("ip")
    if not is_ip(ip):
        return None
    ts = _parse_time(m.group("time"))
    if ts is None:
        return None

    request = m.group("request")
    req = _REQUEST.match(request)
    method = req.group("method") if req else ""
    uri_raw = req.group("uri") if req else ""
    protocol = (req.group("proto") or "") if req else ""
    uri, rounds = decode_uri(uri_raw)
    path = uri.split("?", 1)[0]

    status = int(m.group("status"))
    size = m.group("bytes")
    ruser = m.group("ruser")

    event_type = "http_request"
    norm_path = path.rstrip("/").lower() or "/"
    if method == "POST" and norm_path in LOGIN_PATHS and status in (401, 403):
        event_type = "http_login_failed"

    return Event(
        ts=ts,
        source="nginx",
        event_type=event_type,
        src_ip=ip,
        user="" if ruser == "-" else ruser,
        raw=raw,
        fields={
            "method": method,
            "uri": uri,
            "uri_raw": uri_raw,
            "path": path,
            "decode_rounds": rounds,
            "protocol": protocol,
            "request": request,
            "status": status,
            "bytes": 0 if size == "-" else int(size),
            "referer": m.group("referer") or "",
            "user_agent": m.group("ua") or "",
        },
    )
