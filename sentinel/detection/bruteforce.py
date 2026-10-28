"""Credential attack rules: SENTINEL-001, SENTINEL-002 and SENTINEL-006."""

from __future__ import annotations

from abc import abstractmethod
from typing import Any, Deque, Optional

from sentinel.config import Settings
from sentinel.detection.base import Detector, epoch
from sentinel.detection.window import Entry, LRUDict, SlidingWindow, iso
from sentinel.models import Alert, Event, Severity


class _FailureThresholdDetector(Detector):
    """Counts failures per source IP in a sliding window.

    Fires when the count exceeds ``threshold`` (High), at most once per IP per
    cooldown. The one exception is a single escalation alert when the count
    reaches ``critical`` inside the cooldown.
    """

    def __init__(self, settings: Optional[Settings] = None) -> None:
        super().__init__(settings)
        s = self.settings
        self.threshold, self.critical, self.window_s = self._limits()
        self._window = SlidingWindow(self.window_s, s.window_max_events_per_key,
                                     s.window_max_keys)
        self._fired: LRUDict = LRUDict(s.window_max_keys)    # ip -> (ts, severity)
        self._tripped: LRUDict = LRUDict(s.window_max_keys)  # ip -> latest breach ts

    @abstractmethod
    def _limits(self) -> tuple[int, int, int]:
        """(threshold, critical, window_s)"""

    @abstractmethod
    def _is_failure(self, event: Event) -> bool:
        ...

    def _is_duplicate(self, event: Event, ts: float) -> bool:
        return False

    def tripped_at(self, src_ip: str) -> Optional[float]:
        """Event time of the most recent threshold breach for ``src_ip``, if any."""
        return self._tripped.get(src_ip)

    def evaluate(self, event: Event) -> list[Alert]:
        ip = event.src_ip
        if not ip or not self._is_failure(event):
            return []
        ts = epoch(event)
        if self._is_duplicate(event, ts):
            return []
        dq = self._window.add(ip, ts, event.user)
        count = len(dq)
        if count <= self.threshold:
            return []

        prev = self._tripped.get(ip)
        self._tripped[ip] = ts if prev is None else max(prev, ts)

        severity: Severity = "Critical" if count >= self.critical else "High"
        last = self._fired.get(ip)
        if last is not None and abs(ts - last[0]) < self.settings.alert_cooldown_s:
            if severity != "Critical" or last[1] == "Critical":
                return []
        self._fired[ip] = (ts, severity)
        return [self._build(event, severity, self._evidence(dq, count))]

    def _evidence(self, dq: Deque[Entry], count: int) -> dict[str, Any]:
        users = sorted({u for _, u in dq if u})
        return {
            "failures": count,
            "threshold": self.threshold,
            "window_s": self.window_s,
            "first_seen": iso(dq[0][0]),
            "last_seen": iso(dq[-1][0]),
            "distinct_users": len(users),
            "users": users[:20],
        }

    def _build(self, event: Event, severity: Severity, evidence: dict[str, Any]) -> Alert:
        return self.make_alert(event, severity, evidence)


class SSHBruteForce(_FailureThresholdDetector):
    rule_id = "SENTINEL-001"
    title = "SSH Brute Force"
    mitre_technique = "T1110.001"

    def __init__(self, settings: Optional[Settings] = None) -> None:
        super().__init__(settings)
        # (ip, user, reason) -> ts of an unpaired invalid-user half
        self._pending: LRUDict = LRUDict(self.settings.window_max_keys)

    def _limits(self) -> tuple[int, int, int]:
        s = self.settings
        return s.ssh_bruteforce_threshold, s.ssh_bruteforce_critical, s.ssh_bruteforce_window_s

    def _is_failure(self, event: Event) -> bool:
        return event.source == "ssh" and event.event_type == "ssh_failed"

    def _is_duplicate(self, event: Event, ts: float) -> bool:
        """sshd logs one bad-username attempt twice: "Invalid user X" and then
        "Failed password for invalid user X". Count the pair once, in either order."""
        reason = event.fields.get("reason")
        if not event.fields.get("invalid_user") or reason not in ("invalid_user", "failed_auth"):
            return False
        partner = "failed_auth" if reason == "invalid_user" else "invalid_user"
        partner_key = (event.src_ip, event.user, partner)
        partner_ts = self._pending.get(partner_key)
        gap = self.settings.ssh_invalid_user_dedupe_s
        if partner_ts is not None and abs(ts - partner_ts) <= gap:
            del self._pending[partner_key]
            return True
        self._pending[(event.src_ip, event.user, reason)] = ts
        return False


class WebLoginBruteForce(_FailureThresholdDetector):
    rule_id = "SENTINEL-002"
    title = "Web/VPN Login Brute Force"
    mitre_technique = "T1110.001"

    def _limits(self) -> tuple[int, int, int]:
        s = self.settings
        return (s.http_login_fail_threshold, s.http_login_fail_critical,
                s.http_login_fail_window_s)

    def _is_failure(self, event: Event) -> bool:
        if event.event_type == "http_login_failed":
            return True
        return event.event_type == "vpn_login" and event.fields.get("success") is False

    def _build(self, event: Event, severity: Severity, evidence: dict[str, Any]) -> Alert:
        if evidence["distinct_users"] >= self.settings.web_spray_distinct_users:
            return self.make_alert(event, severity, evidence,
                                   title="Password Spraying / Credential Stuffing",
                                   mitre_technique="T1110.003")
        return self.make_alert(event, severity, evidence)


class SuccessAfterBruteForce(Detector):
    rule_id = "SENTINEL-006"
    title = "Successful Login After Brute Force"
    mitre_technique = "T1078"

    def __init__(self, settings: Optional[Settings] = None,
                 bruteforce: Optional[SSHBruteForce] = None) -> None:
        super().__init__(settings)
        # The engine passes its shared SENTINEL-001 instance. Standalone, we feed our own.
        self._owns_bf = bruteforce is None
        self._bf = bruteforce if bruteforce is not None else SSHBruteForce(self.settings)
        self._fired: LRUDict = LRUDict(self.settings.window_max_keys)

    def evaluate(self, event: Event) -> list[Alert]:
        if self._owns_bf:
            self._bf.evaluate(event)
        if event.source != "ssh" or event.event_type != "ssh_success" or not event.src_ip:
            return []
        tripped = self._bf.tripped_at(event.src_ip)
        if tripped is None:
            return []
        ts = epoch(event)
        delta = ts - tripped
        if delta < 0 or delta > self.settings.success_after_bf_window_s:
            return []
        key = (event.src_ip, event.user)
        last = self._fired.get(key)
        if last is not None and abs(ts - last) < self.settings.alert_cooldown_s:
            return []
        self._fired[key] = ts
        return [self.make_alert(event, "Critical", {
            "bruteforce_tripped_at": iso(tripped),
            "seconds_after_bruteforce": round(delta, 3),
            "auth_method": event.fields.get("auth_method"),
        })]
