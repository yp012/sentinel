"""SENTINEL-005: physical/digital identity anomaly.

Correlates badge swipes at the secure facility with remote and on-prem logins:

a) A successful VPN login from an external IP while the user is badged "in" at
   the facility (latest granted swipe at or before the login is "in", within
   ``onsite_window_s``).
b) An on-prem SSH login (from an internal CIDR) with no granted badge-in at the
   facility within ``badge_lookback_s`` before it.

All window logic uses ``event.ts``. Badge history is kept sorted by time, so a
late-arriving swipe still counts for later events. A late badge-in also
re-checks recent external VPN logins it would have made suspicious (case a).
"""

from __future__ import annotations

import ipaddress
from bisect import bisect_right
from collections import deque
from typing import Optional

from sentinel.config import Settings
from sentinel.detection.base import Detector, epoch
from sentinel.detection.window import LRUDict, evict_before, insort_ts, iso
from sentinel.models import Alert, Event


class ImpossibleTravel(Detector):
    rule_id = "SENTINEL-005"
    title = "Impossible Travel / Physical-Digital Anomaly"
    mitre_technique = "T1078"

    def __init__(self, settings: Optional[Settings] = None) -> None:
        super().__init__(settings)
        s = self.settings
        self._internal = tuple(ipaddress.ip_network(c, strict=False) for c in s.internal_cidrs)
        self._facility = s.secure_facility.strip().lower()
        self._retention = max(s.onsite_window_s, s.badge_lookback_s)
        self._swipes: LRUDict = LRUDict(s.window_max_keys)     # user -> deque[(ts, dir)]
        self._vpn: LRUDict = LRUDict(s.window_max_keys)        # user -> deque[(ts, Event)]
        self._badge_holders: LRUDict = LRUDict(s.window_max_keys)
        self._fired: LRUDict = LRUDict(s.window_max_keys)

    # ------------------------------------------------------------------ helpers

    def is_internal(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self._internal)

    def is_external(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        if addr.is_loopback or addr.is_link_local or addr.is_unspecified:
            return False
        return not any(addr in net for net in self._internal)

    def _at_facility(self, event: Event) -> bool:
        if not self._facility:
            return True
        return str(event.fields.get("facility", "")).strip().lower() == self._facility

    def _last_swipe(self, user: str, ts: float) -> Optional[tuple[float, str]]:
        dq = self._swipes.get(user)
        if not dq:
            return None
        idx = bisect_right(dq, ts, key=lambda e: e[0])
        return dq[idx - 1] if idx else None

    def _badged_in_between(self, user: str, start: float, end: float) -> bool:
        dq = self._swipes.get(user)
        if not dq:
            return False
        return any(start <= t <= end and d == "in" for t, d in dq)

    # ---------------------------------------------------------------- evaluate

    def evaluate(self, event: Event) -> list[Alert]:
        if not event.user:
            return []
        if event.event_type == "badge_swipe":
            return self._on_badge(event)
        if event.event_type == "vpn_login":
            return self._on_vpn(event)
        if event.event_type == "ssh_success":
            return self._on_ssh(event)
        return []

    def _on_badge(self, event: Event) -> list[Alert]:
        user = event.user
        self._badge_holders[user] = True
        if event.fields.get("granted") is not True or not self._at_facility(event):
            return []
        direction = event.fields.get("direction")
        if direction not in ("in", "out"):
            return []
        ts = epoch(event)
        dq = self._swipes.get(user)
        if dq is None:
            dq = deque(maxlen=self.settings.window_max_events_per_key)
        self._swipes[user] = dq
        insort_ts(dq, (ts, direction))
        evict_before(dq, dq[-1][0] - self._retention)

        if direction != "in":
            return []
        # Out-of-order: re-check external VPN logins that happened after this badge-in.
        alerts = []
        for vpn_ts, vpn_event in list(self._vpn.get(user) or ()):
            if vpn_ts >= ts:
                alert = self._check_onsite_vpn(vpn_event, vpn_ts, trigger=event)
                if alert is not None:
                    alerts.append(alert)
        return alerts

    def _on_vpn(self, event: Event) -> list[Alert]:
        if event.fields.get("success") is not True or not self.is_external(event.src_ip):
            return []
        ts = epoch(event)
        dq = self._vpn.get(event.user)
        if dq is None:
            dq = deque(maxlen=self.settings.window_max_events_per_key)
        self._vpn[event.user] = dq
        insort_ts(dq, (ts, event))
        evict_before(dq, dq[-1][0] - self.settings.onsite_window_s)
        alert = self._check_onsite_vpn(event, ts, trigger=event)
        return [alert] if alert is not None else []

    def _check_onsite_vpn(self, vpn: Event, vpn_ts: float, trigger: Event) -> Optional[Alert]:
        last = self._last_swipe(vpn.user, vpn_ts)
        if last is None or last[1] != "in":
            return None
        badge_ts = last[0]
        if vpn_ts - badge_ts > self.settings.onsite_window_s:
            return None
        key = ("vpn", vpn.user, vpn_ts, vpn.src_ip)
        if key in self._fired:
            return None
        self._fired[key] = vpn_ts
        return self.make_alert(trigger, "Critical", {
            "scenario": "remote_login_while_onsite",
            "facility": self.settings.secure_facility,
            "badge_in_at": iso(badge_ts),
            "vpn_login_at": iso(vpn_ts),
            "vpn_src_ip": vpn.src_ip,
            "seconds_since_badge_in": round(vpn_ts - badge_ts, 3),
        }, src_ip=vpn.src_ip, user=vpn.user)

    def _on_ssh(self, event: Event) -> list[Alert]:
        if event.source != "ssh" or not self.is_internal(event.src_ip):
            return []
        user = event.user
        if self.settings.require_known_badge and user not in self._badge_holders:
            return []
        ts = epoch(event)
        lookback = self.settings.badge_lookback_s
        if self._badged_in_between(user, ts - lookback, ts):
            return []
        key = ("ssh", user)
        last = self._fired.get(key)
        if last is not None and abs(ts - last) < self.settings.alert_cooldown_s:
            return []
        self._fired[key] = ts
        return [self.make_alert(event, "Critical", {
            "scenario": "onprem_access_without_badge_in",
            "facility": self.settings.secure_facility,
            "ssh_login_at": iso(ts),
            "lookback_s": lookback,
            "host": event.fields.get("host"),
        })]
