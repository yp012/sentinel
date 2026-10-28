"""Runs every detector over each event, isolating failures per rule."""

from __future__ import annotations

import logging
from collections import Counter
from typing import Optional, Sequence

from sentinel import config
from sentinel.config import Settings
from sentinel.detection.base import Detector
from sentinel.detection.bruteforce import SSHBruteForce, SuccessAfterBruteForce, WebLoginBruteForce
from sentinel.detection.impossible_travel import ImpossibleTravel
from sentinel.detection.web_attack import PathTraversal, SQLInjection
from sentinel.models import Alert, Event

logger = logging.getLogger(__name__)

DETECTOR_CLASSES: tuple[type[Detector], ...] = (
    SSHBruteForce,
    WebLoginBruteForce,
    SQLInjection,
    PathTraversal,
    ImpossibleTravel,
    SuccessAfterBruteForce,
)

# Rule metadata for the benchmark/README: [{"id", "title", "mitre"}, ...]
RULES: tuple[dict[str, str], ...] = tuple(cls.metadata() for cls in DETECTOR_CLASSES)


def default_detectors(settings: Optional[Settings] = None) -> list[Detector]:
    s = settings or config.settings
    ssh_bf = SSHBruteForce(s)
    return [
        ssh_bf,
        WebLoginBruteForce(s),
        SQLInjection(s),
        PathTraversal(s),
        ImpossibleTravel(s),
        # Shares SENTINEL-001 state; must run after it.
        SuccessAfterBruteForce(s, bruteforce=ssh_bf),
    ]


class DetectionEngine:
    RULES = RULES

    def __init__(self, detectors: Optional[Sequence[Detector]] = None,
                 settings: Optional[Settings] = None) -> None:
        self.detectors: list[Detector] = (
            list(detectors) if detectors is not None else default_detectors(settings)
        )
        self.errors: Counter[str] = Counter()

    def process(self, event: Event) -> list[Alert]:
        alerts: list[Alert] = []
        for detector in self.detectors:
            try:
                alerts.extend(detector.evaluate(event))
            except Exception:
                self.errors[detector.rule_id] += 1
                logger.exception("detector %s failed on %s event", detector.rule_id,
                                 event.event_type)
        return alerts
