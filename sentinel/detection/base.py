"""Detector base class.

Detectors must never read ``Event.label`` (ground truth for the benchmark only),
and must stamp alerts with the triggering event's ``ingested_ns``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, ClassVar, Optional

from sentinel import config
from sentinel.config import Settings
from sentinel.models import Alert, Event, Severity


def epoch(event: Event) -> float:
    return event.ts.timestamp()


class Detector(ABC):
    rule_id: ClassVar[str] = ""
    title: ClassVar[str] = ""
    mitre_technique: ClassVar[str] = ""

    def __init__(self, settings: Optional[Settings] = None) -> None:
        self.settings = settings or config.settings

    @abstractmethod
    def evaluate(self, event: Event) -> list[Alert]:
        """Return zero or more alerts for this event. May update internal state."""

    @classmethod
    def metadata(cls) -> dict[str, str]:
        return {"id": cls.rule_id, "title": cls.title, "mitre": cls.mitre_technique}

    def make_alert(
        self,
        event: Event,
        severity: Severity,
        evidence: dict[str, Any],
        *,
        title: Optional[str] = None,
        mitre_technique: Optional[str] = None,
        src_ip: Optional[str] = None,
        user: Optional[str] = None,
    ) -> Alert:
        return Alert(
            rule_id=self.rule_id,
            title=title or self.title,
            mitre_technique=mitre_technique or self.mitre_technique,
            severity=severity,
            src_ip=event.src_ip if src_ip is None else src_ip,
            user=event.user if user is None else user,
            evidence=evidence,
            # MTTD is measured from ingestion of the event that completed the evidence.
            detected_at_ns=event.ingested_ns,
        )
