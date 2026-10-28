"""OpenSSH auth.log parser.

Handles both classic syslog timestamps (``Oct 27 10:15:32``, no year) and
RFC 3339 timestamps written by modern rsyslog/journald forwarders.

Usernames are attacker-controlled, so the message patterns are anchored at the end
of the line and the username group is greedy: a username such as
``x from 6.6.6.6 port 22`` cannot smuggle in a fake source IP.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Optional

from sentinel.models import Event
from sentinel.parsers._common import MONTHS, is_ip, parse_iso_ts

_PREFIX = re.compile(
    r"^(?:"
    r"(?P<mon>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
    r"|(?P<iso>\d{4}-\d{2}-\d{2}T\S+)"
    r")\s+(?P<host>\S+)\s+sshd(?:-session)?(?:\[(?P<pid>\d+)\])?:\s(?P<msg>.*)$"
)

_FAILED = re.compile(
    r"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>.*) "
    r"from (?P<ip>\S+) port (?P<port>\d+)(?: ssh2)?$"
)
_ACCEPTED = re.compile(
    r"^Accepted (?P<method>\S+) for (?P<user>.*) "
    r"from (?P<ip>\S+) port (?P<port>\d+)(?: ssh2(?:: \S+ \S+)?)?$"
)
_INVALID = re.compile(
    r"^Invalid user (?P<user>.*) from (?P<ip>\S+)(?: port (?P<port>\d+))?$"
)


def _syslog_ts(mon: str, day: str, clock: str, now: datetime) -> Optional[datetime]:
    month = MONTHS.get(mon.lower())
    if month is None:
        return None
    try:
        hh, mm, ss = (int(p) for p in clock.split(":"))
        ts = datetime(now.year, month, int(day), hh, mm, ss, tzinfo=timezone.utc)
    except ValueError:
        return None
    # No year in syslog: a December line read in early January belongs to last year.
    if ts - now > timedelta(days=1):
        try:
            ts = ts.replace(year=now.year - 1)
        except ValueError:  # Feb 29 in a non-leap previous year
            return None
    return ts


def parse_line(line: str, *, now: Optional[datetime] = None) -> Optional[Event]:
    try:
        return _parse(line, now)
    except Exception:  # parsers must never raise on bad input
        return None


def _parse(line: str, now: Optional[datetime]) -> Optional[Event]:
    raw = line.rstrip("\r\n")
    head = _PREFIX.match(raw)
    if head is None:
        return None

    if head.group("iso"):
        ts = parse_iso_ts(head.group("iso"))
    else:
        ts = _syslog_ts(
            head.group("mon"), head.group("day"), head.group("time"),
            now or datetime.now(timezone.utc),
        )
    if ts is None:
        return None

    msg = head.group("msg")
    fields: dict = {"host": head.group("host"), "pid": head.group("pid")}

    m = _FAILED.match(msg)
    if m:
        event_type = "ssh_failed"
        fields.update(
            auth_method=m.group("method"),
            invalid_user=bool(m.group("invalid")),
            reason="failed_auth",
        )
    else:
        m = _ACCEPTED.match(msg)
        if m:
            event_type = "ssh_success"
            fields.update(auth_method=m.group("method"), invalid_user=False)
        else:
            m = _INVALID.match(msg)
            if m is None:
                return None
            # sshd logs this before the "Failed password for invalid user" line,
            # so detectors counting attempts can key on fields["reason"] to dedupe.
            event_type = "ssh_failed"
            fields.update(auth_method=None, invalid_user=True, reason="invalid_user")

    ip = m.group("ip")
    if not is_ip(ip):
        return None
    port = m.group("port")
    fields["port"] = int(port) if port else None

    return Event(
        ts=ts,
        source="ssh",
        event_type=event_type,
        src_ip=ip,
        user=m.group("user"),
        raw=raw,
        fields=fields,
    )
