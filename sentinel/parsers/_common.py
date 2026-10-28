"""Helpers shared by the parsers."""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Optional

MONTHS = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
    "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def parse_iso_ts(value: object) -> Optional[datetime]:
    """ISO-8601 string (``Z`` allowed) or epoch seconds -> aware UTC datetime."""
    try:
        if isinstance(value, bool):
            return None
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value, tz=timezone.utc)
        if not isinstance(value, str):
            return None
        text = value.strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
    except (ValueError, OverflowError, OSError):
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)
