import ast
import logging
import re
from pathlib import Path

from sentinel.detection import RULES, DetectionEngine, Detector, SQLInjection
from tests.factories import http_get, settings, ssh_failed, ssh_success


class Exploding(Detector):
    rule_id = "TEST-BOOM"
    title = "Always raises"
    mitre_technique = "T0000"

    def evaluate(self, event):
        raise RuntimeError("boom")


def test_rules_metadata():
    ids = [r["id"] for r in RULES]
    assert ids == [f"SENTINEL-00{i}" for i in range(1, 7)]
    assert all(r["title"] and re.fullmatch(r"T\d{4}(\.\d{3})?", r["mitre"]) for r in RULES)
    assert DetectionEngine.RULES is RULES


def test_engine_runs_all_rules_end_to_end():
    engine = DetectionEngine(settings=settings())
    alerts = []
    for i in range(6):
        alerts += engine.process(ssh_failed(t=i))
    alerts += engine.process(ssh_success(t=10))
    alerts += engine.process(http_get("/q?id=1%20UNION%20SELECT%201,2--%20"))
    alerts += engine.process(http_get("/f?p=../../etc/passwd"))
    assert [a.rule_id for a in alerts] == [
        "SENTINEL-001", "SENTINEL-006", "SENTINEL-003", "SENTINEL-004",
    ]
    assert engine.errors == {}


def test_detector_exception_is_isolated(caplog):
    engine = DetectionEngine([Exploding(settings()), SQLInjection(settings())])
    ev = http_get("/q?id=1%20UNION%20SELECT%201,2--%20")
    with caplog.at_level(logging.ERROR, logger="sentinel.detection.engine"):
        alerts = engine.process(ev)
        alerts += engine.process(ev)
    assert [a.rule_id for a in alerts] == ["SENTINEL-003", "SENTINEL-003"]
    assert engine.errors["TEST-BOOM"] == 2
    assert "TEST-BOOM" in caplog.text
    assert "boom" in caplog.text


def test_label_does_not_change_detection():
    def run(label):
        engine = DetectionEngine(settings=settings())
        out = []
        for i in range(6):
            ev = ssh_failed(t=i)
            ev.label = label
            out += engine.process(ev)
        return [(a.rule_id, a.severity) for a in out]

    assert run(None) == run("attack") == run("benign")


def test_detection_source_never_reads_label():
    pkg = Path(__file__).resolve().parents[1] / "sentinel" / "detection"
    for path in pkg.glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            assert not (isinstance(node, ast.Attribute) and node.attr == "label"), path
            assert not (isinstance(node, ast.Constant) and node.value == "label"), path
