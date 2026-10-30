import ast
import time
from pathlib import Path

import pytest

from sentinel.models import Event
from sentinel.parsers import parse_any
from sentinel.pipeline import Pipeline
from sentinel.store import IncidentStore
from tests.factories import settings

ATTACKER = "203.0.113.7"


def ssh_fail(i: int, ip: str = ATTACKER, user: str = "root") -> str:
    return (f"2026-10-27T10:00:{i % 60:02d}Z bastion01 sshd[{100 + i}]: "
            f"Failed password for {user} from {ip} port {40000 + i} ssh2")


def make_pipeline(tmp_path: Path, **kw) -> Pipeline:
    s = settings(abuseipdb_api_key="", webhook_url="", api_key="", log_paths=(),
                 tail_poll_interval_s=0.01)
    return Pipeline(s, data_dir=str(tmp_path), **kw)


class RecordingParser:
    """parse_any plus the monotonic time of each call and the events it produced."""

    def __init__(self):
        self.calls: list[int] = []
        self.events: list[Event] = []

    def __call__(self, line: str):
        self.calls.append(time.monotonic_ns())
        event = parse_any(line)
        if event is not None:
            self.events.append(event)
        return event


# ------------------------------------------------------------------ timing

def test_ingested_ns_is_captured_before_parsing(tmp_path):
    parser = RecordingParser()
    pipe = make_pipeline(tmp_path, parser=parser)
    before = time.monotonic_ns()
    pipe.ingest(ssh_fail(0))
    event = parser.events[0]
    # The parser's own Event default (taken during parsing) was replaced by t_ingest.
    assert before <= event.ingested_ns <= parser.calls[0]


def test_event_input_gets_fresh_ingest_timestamp(tmp_path):
    pipe = make_pipeline(tmp_path)
    event = parse_any(ssh_fail(0))
    event.ingested_ns = 1
    before = time.monotonic_ns()
    pipe.ingest(event)
    assert event.ingested_ns >= before


def test_mttd_and_mttr_are_measured_from_ingestion(tmp_path):
    parser = RecordingParser()
    pipe = make_pipeline(tmp_path, parser=parser)
    ids = ()
    for i in range(6):  # threshold 5: the 6th failure fires SENTINEL-001 High
        ids = pipe.ingest(ssh_fail(i)) or ids
    assert len(ids) == 1
    incident = pipe.store.get(ids[0])
    trigger = parser.events[-1]

    assert incident.alert["detected_at_ns"] == trigger.ingested_ns == incident.ingested_ns
    assert incident.mttd_ns == incident.detected_ns - trigger.ingested_ns
    assert incident.mttd_ns >= 0

    block = next(e for e in incident.timeline
                 if e.get("name") == "block_ip_firewall")
    assert block["status"] == "success"
    assert incident.mttr_ns == block["finished_ns"] - trigger.ingested_ns
    assert incident.mttr_ns > incident.mttd_ns
    assert incident.status == "contained"

    m = pipe.store.metrics()
    assert m["mttd"]["count"] == 1 and m["mttr"]["count"] == 1
    assert m["mttr"]["mean_ms"] == pytest.approx(incident.mttr_ns / 1e6, abs=1e-3)


def test_no_mttr_when_nothing_was_blocked(tmp_path):
    pipe = make_pipeline(tmp_path)
    ids = ()
    for i in range(6):  # private source: the firewall guard refuses the block
        ids = pipe.ingest(ssh_fail(i, ip="10.0.5.10")) or ids
    incident = pipe.store.get(ids[0])
    assert incident.mttd_ns is not None
    assert incident.mttr_ns is None
    assert incident.status == "open"
    assert pipe.store.metrics()["mttr"]["count"] == 0


# ----------------------------------------------------------------- batches

def test_batch_isolates_failures(tmp_path):
    def flaky(line):
        if line == "BOOM":
            raise RuntimeError("parser exploded")
        return parse_any(line)

    pipe = make_pipeline(tmp_path, parser=flaky)
    items = [ssh_fail(0), "BOOM", 42, "not a log line", *[ssh_fail(i) for i in range(1, 6)]]
    result = pipe.ingest_batch(items)

    assert result.received == len(items)
    assert result.errors == [{"index": 1, "error": "RuntimeError"},
                             {"index": 2, "error": "TypeError"}]
    assert result.unparsed == 1
    assert result.parsed == 6
    assert result.alerts == 1 and len(result.incidents) == 1  # later lines still detected

    m = pipe.store.metrics()
    assert m["lines_received"] == len(items)
    assert m["events_ingested"] == 6
    assert m["lines_unparsed"] == 1
    assert m["ingest_errors"] == 2
    assert m["events_by_source"] == {"ssh": 6}


def test_batch_survives_a_failing_store(tmp_path):
    class BrokenStore(IncidentStore):
        def add_response(self, response, *, detected_ns):
            raise OSError("disk full")

    pipe = make_pipeline(tmp_path, store=BrokenStore(""))
    result = pipe.ingest_batch([ssh_fail(i) for i in range(8)])
    assert result.parsed == 8
    assert [e["error"] for e in result.errors] == ["OSError"]  # only the alerting line


def test_counters_and_eps_series(tmp_path):
    pipe = make_pipeline(tmp_path)
    pipe.ingest_batch([ssh_fail(i) for i in range(25)])
    m = pipe.store.metrics()
    assert m["events_ingested"] == 25
    assert sum(p["count"] for p in m["events_per_sec"]["points"]) == 25
    assert m["alerts_by_severity"] == {"Low": 0, "Medium": 0, "High": 1, "Critical": 1}
    assert m["alerts_by_technique"] == {"T1110.001": 2}
    assert m["incidents_total"] == 1


# ------------------------------------------------------------ store/persistence

def test_incidents_persist_to_sqlite(tmp_path):
    db = tmp_path / "incidents.db"
    pipe = make_pipeline(tmp_path, db_path=str(db))
    pipe.ingest_batch([ssh_fail(i) for i in range(6)])
    [incident] = pipe.store.list_incidents()
    pipe.close()

    reloaded = IncidentStore(str(db), settings=pipe.settings)
    assert reloaded.get_dict(incident["id"])["severity"] == "High"
    # Still the merge target after a restart: escalation lands on the same incident.
    pipe2 = make_pipeline(tmp_path, store=reloaded)
    pipe2.ingest_batch([ssh_fail(i) for i in range(21)])
    assert len(reloaded) == 1
    assert reloaded.get(incident["id"]).severity == "Critical"
    reloaded.close()


def test_resolved_incident_is_not_merged_into(tmp_path):
    pipe = make_pipeline(tmp_path)
    pipe.ingest_batch([ssh_fail(i) for i in range(6)])
    [first] = pipe.store.list_incidents()
    pipe.store.set_status(first["id"], "resolved", note="handled")
    # A fresh detector state (new pipeline, same store) alerts again for the same IP.
    pipe2 = make_pipeline(tmp_path, store=pipe.store)
    pipe2.ingest_batch([ssh_fail(i) for i in range(6)])
    assert len(pipe.store) == 2
    assert pipe.store.get(first["id"]).status == "resolved"


# ----------------------------------------------------------------- tailing

def test_tails_log_paths(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("".join(ssh_fail(i) + "\n" for i in range(3)))
    s = settings(abuseipdb_api_key="", webhook_url="", tail_poll_interval_s=0.01,
                 log_paths=(str(log),))
    pipe = Pipeline(s, data_dir=str(tmp_path))
    assert pipe.start_tailing(from_start=True) == [str(log)]
    with log.open("a") as fh:
        fh.write("".join(ssh_fail(i) + "\n" for i in range(3, 6)))
    deadline = time.monotonic() + 5
    while pipe.store.metrics()["events_ingested"] < 6 and time.monotonic() < deadline:
        time.sleep(0.01)
    pipe.close()
    assert not pipe.tailing
    assert pipe.store.metrics()["events_ingested"] == 6
    assert len(pipe.store) == 1


# ------------------------------------------------------------------ labels

def test_pipeline_store_api_never_read_label():
    root = Path(__file__).resolve().parents[1] / "sentinel"
    for name in ("pipeline.py", "store.py", "api.py"):
        path = root / name
        for node in ast.walk(ast.parse(path.read_text())):
            assert not (isinstance(node, ast.Attribute) and node.attr == "label"), path
            assert not (isinstance(node, ast.Constant) and node.value == "label"), path


def test_label_does_not_change_outcome(tmp_path):
    def run(tag, sub):
        pipe = make_pipeline(tmp_path / sub)
        for i in range(25):
            event = parse_any(ssh_fail(i))
            event.label = tag
            pipe.ingest(event)
        return [(i["severity"], i["alert_count"]) for i in pipe.store.list_incidents()]

    assert run(None, "a") == run("attack", "b") == run("benign", "c")
