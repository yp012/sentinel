"""Small builders shared by the detection tests."""

from __future__ import annotations

import dataclasses
import itertools
from datetime import datetime, timedelta, timezone

from sentinel.config import Settings
from sentinel.models import Event
from sentinel.parsers import nginx

BASE = datetime(2026, 10, 27, 10, 0, 0, tzinfo=timezone.utc)

# Deliberately far from any real monotonic clock reading, so a detector that used
# time.monotonic_ns() instead of event.ingested_ns would be caught.
_ingest = itertools.count(1_000)


def settings(**overrides) -> Settings:
    return dataclasses.replace(Settings(), **overrides)


def make_event(source, event_type, *, t=0.0, ip="203.0.113.7", user="root", **fields) -> Event:
    return Event(
        ts=BASE + timedelta(seconds=t),
        source=source,
        event_type=event_type,
        src_ip=ip,
        user=user,
        raw="test",
        fields=fields,
        ingested_ns=next(_ingest),
    )


def ssh_failed(t=0.0, ip="203.0.113.7", user="root", reason="failed_auth", invalid=False):
    return make_event("ssh", "ssh_failed", t=t, ip=ip, user=user,
                      reason=reason, invalid_user=invalid, auth_method="password")


def ssh_success(t=0.0, ip="203.0.113.7", user="root"):
    return make_event("ssh", "ssh_success", t=t, ip=ip, user=user,
                      auth_method="password", invalid_user=False, host="bastion01")


def http_login_failed(t=0.0, ip="198.51.100.9", user=""):
    return make_event("nginx", "http_login_failed", t=t, ip=ip, user=user,
                      method="POST", path="/login", status=401)


def vpn_login(t=0.0, ip="198.51.100.20", user="alice", success=True):
    return make_event("vpn", "vpn_login", t=t, ip=ip, user=user, success=success)


def badge(t=0.0, user="alice", direction="in", granted=True, facility="HQ"):
    return make_event("pacs", "badge_swipe", t=t, ip="", user=user, badge_id="B-1",
                      door="D-1", facility=facility, direction=direction, granted=granted)


def http_get(uri: str, ip="198.51.100.66", status=200) -> Event:
    line = (f'{ip} - - [27/Oct/2026:10:00:00 +0000] "GET {uri} HTTP/1.1" '
            f'{status} 0 "-" "Mozilla/5.0"')
    event = nginx.parse_line(line)
    assert event is not None, line
    return event
