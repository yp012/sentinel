"""Physical access control (badge reader) CSV parser.

Columns: ``ts,badge_id,user,door,facility,direction,granted``. A header row is
ignored (returns None). Badge swipes have no network origin, so ``src_ip`` is empty.
"""

from __future__ import annotations

import csv
from typing import Optional

from sentinel.models import Event
from sentinel.parsers._common import parse_iso_ts

COLUMNS = ("ts", "badge_id", "user", "door", "facility", "direction", "granted")

_TRUE = {"true", "1", "yes", "y", "granted"}
_FALSE = {"false", "0", "no", "n", "denied"}
_DIRECTIONS = {"in", "out"}


def parse_line(line: str) -> Optional[Event]:
    try:
        return _parse(line)
    except Exception:  # parsers must never raise on bad input
        return None


def _parse(line: str) -> Optional[Event]:
    raw = line.rstrip("\r\n")
    try:
        rows = list(csv.reader([raw]))
    except csv.Error:
        return None
    if len(rows) != 1 or len(rows[0]) != len(COLUMNS):
        return None
    ts_s, badge_id, user, door, facility, direction, granted_s = (c.strip() for c in rows[0])

    ts = parse_iso_ts(ts_s)
    if ts is None:
        return None  # also rejects the header row
    direction = direction.lower()
    if direction not in _DIRECTIONS:
        return None
    granted_l = granted_s.lower()
    if granted_l in _TRUE:
        granted = True
    elif granted_l in _FALSE:
        granted = False
    else:
        return None
    if not badge_id or not user:
        return None

    return Event(
        ts=ts,
        source="pacs",
        event_type="badge_swipe",
        src_ip="",
        user=user,
        raw=raw,
        fields={
            "badge_id": badge_id,
            "door": door,
            "facility": facility,
            "direction": direction,
            "granted": granted,
        },
    )
