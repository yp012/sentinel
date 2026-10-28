"""Detection rules and the engine that runs them."""

from sentinel.detection.base import Detector
from sentinel.detection.bruteforce import SSHBruteForce, SuccessAfterBruteForce, WebLoginBruteForce
from sentinel.detection.engine import RULES, DetectionEngine, default_detectors
from sentinel.detection.impossible_travel import ImpossibleTravel
from sentinel.detection.web_attack import PathTraversal, SQLInjection

__all__ = [
    "RULES",
    "DetectionEngine",
    "Detector",
    "ImpossibleTravel",
    "PathTraversal",
    "SQLInjection",
    "SSHBruteForce",
    "SuccessAfterBruteForce",
    "WebLoginBruteForce",
    "default_detectors",
]
