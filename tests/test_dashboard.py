"""Dashboard data/formatting helpers, with ``requests`` stubbed (no network)."""

import ast
import pathlib

import pytest
import requests

from dashboard import data as d

ROOT = pathlib.Path(__file__).resolve().parents[1]
INC_ID = "INC-0123456789ab"


class FakeResponse:
    def __init__(self, status_code=200, body=None, *, raw_text=False):
        self.status_code = status_code
        self._body = body
        self._raw_text = raw_text

    def json(self):
        if self._raw_text:
            raise ValueError("not json")
        return self._body


class Calls(list):
    """Recorded requests; each call gets ``self.reply`` (raised if an exception)."""

    reply = FakeResponse(200, {})

    def __call__(self, method, url, **kwargs):
        self.append({"method": method, "url": url, **kwargs})
        if isinstance(self.reply, BaseException):
            raise self.reply
        return self.reply


@pytest.fixture
def calls(monkeypatch):
    log = Calls()
    monkeypatch.setattr(d.requests, "request", log)
    return log


def reply(calls, value):
    calls.reply = value


def metrics_doc(**overrides):
    doc = {
        "uptime_s": 12.0,
        "events_ingested": 1234,
        "alerts_total": 7,
        "alerts_by_technique": {"T1110": 5, "T1190": 2},
        "incidents_by_status": {"open": 3, "contained": 1, "resolved": 0,
                                "false_positive": 0},
        "events_per_sec": {"bucket_s": 1.0, "points": [
            {"t": "2026-11-09T10:00:00+00:00", "count": 10, "eps": 10.0},
            {"t": "2026-11-09T10:00:01+00:00", "count": 20, "eps": 20.0},
            {"t": "2026-11-09T10:00:02+00:00", "count": 3, "eps": 3.0},  # still filling
        ]},
        "mttd": {"count": 4, "mean_ms": 0.42},
        "mttr": {"count": 2, "mean_ms": 1520.0},
        "firewall": {"active_rules": 2, "real": False},
    }
    doc.update(overrides)
    return doc


def incident(sev="High", updated=100.0, ip="203.0.113.5", status="open", inc_id=INC_ID,
             score=90, timeline=None):
    return {"id": inc_id, "rule_id": "SENTINEL-001", "title": "SSH brute force",
            "mitre_technique": "T1110", "severity": sev, "src_ip": ip, "user": "root",
            "status": status, "updated_at": updated, "alert_count": 2,
            "intel": {"ip": ip, "score": score} if score is not None else None,
            "timeline": timeline or [], "actions": []}


# ---------------------------------------------------------------- auth

def test_auth_headers():
    assert d.auth_headers(None) == {}
    assert d.auth_headers("") == {}
    assert d.auth_headers("   ") == {}
    assert d.auth_headers(" k3y ") == {"X-API-Key": "k3y"}
    assert d.API_KEY_HEADER == "X-API-Key"


def test_client_sends_key_header_and_never_shows_it(calls):
    client = d.EngineClient("http://engine:8000/", "s3cret")
    client.metrics()
    assert calls[-1]["url"] == "http://engine:8000/api/metrics"
    assert calls[-1]["headers"] == {"X-API-Key": "s3cret"}
    assert calls[-1]["timeout"] == d.DEFAULT_TIMEOUT_S
    assert "s3cret" not in repr(client)


def test_client_without_key_sends_no_header(calls):
    d.EngineClient("http://engine:8000").health()
    assert calls[-1]["headers"] == {}


def test_engine_url_from_env(monkeypatch):
    monkeypatch.delenv("ENGINE_URL", raising=False)
    assert d.engine_url_from_env() == "http://localhost:8000"
    monkeypatch.setenv("ENGINE_URL", "http://engine:9000/")
    assert d.engine_url_from_env() == "http://engine:9000"


# -------------------------------------------------------------- errors

def test_unreachable_engine_is_a_result_not_an_exception(calls):
    reply(calls, requests.ConnectionError("refused"))
    res = d.EngineClient("http://engine:8000", "k").metrics()
    assert not res.ok and res.unreachable and res.status is None
    assert "unreachable" in res.error and "http://engine:8000" in res.error


def test_timeout(calls):
    reply(calls, requests.Timeout())
    res = d.EngineClient("http://engine:8000").health()
    assert res.unreachable and "timed out" in res.error


def test_unauthorized(calls):
    reply(calls, FakeResponse(401, {"detail": "invalid or missing API key"}))
    res = d.EngineClient("http://e").metrics()
    assert res.unauthorized and not res.unreachable and "API key" in res.error


def test_http_error_carries_detail(calls):
    reply(calls, FakeResponse(503, {"detail": "pipeline not started"}))
    res = d.EngineClient("http://e").metrics()
    assert not res.ok and res.status == 503 and "pipeline not started" in res.error

    reply(calls, FakeResponse(422, {"detail": [{"msg": "bad status"}]}))
    assert "bad status" in d.EngineClient("http://e").metrics().error


def test_non_json_body(calls):
    reply(calls, FakeResponse(200, raw_text=True))
    res = d.EngineClient("http://e").metrics()
    assert not res.ok and "non-JSON" in res.error

    reply(calls, FakeResponse(502, raw_text=True))
    assert d.EngineClient("http://e").metrics().error == "HTTP 502: request failed"


def test_invalid_ids_and_ips_never_hit_the_network(calls):
    client = d.EngineClient("http://e")
    assert not client.contain("../../etc").ok
    assert not client.incident("INC-XYZ").ok
    assert not client.set_status(INC_ID, "deleted").ok
    assert not client.unblock("not-an-ip").ok
    assert calls == []


# --------------------------------------------------------- endpoints

def test_endpoint_paths_and_bodies(calls):
    client = d.EngineClient("http://e")
    client.incidents(limit=5000)
    assert calls[-1]["method"] == "GET" and calls[-1]["url"] == "http://e/api/incidents"
    assert calls[-1]["params"] == {"limit": 1000}   # clamped to the API maximum

    client.contain(INC_ID, note="go")
    assert calls[-1]["method"] == "POST"
    assert calls[-1]["url"] == f"http://e/api/incidents/{INC_ID}/contain"
    assert calls[-1]["json"] == {"note": "go"}

    client.set_status(INC_ID, "false_positive", note="fp")
    assert calls[-1]["url"] == f"http://e/api/incidents/{INC_ID}/status"
    assert calls[-1]["json"] == {"status": "false_positive", "note": "fp"}

    client.unblock(" 2001:db8::1 ")
    assert calls[-1]["method"] == "DELETE"
    assert calls[-1]["url"] == "http://e/api/firewall/rules/2001%3Adb8%3A%3A1"

    client.firewall_rules()
    assert calls[-1]["url"] == "http://e/api/firewall/rules"


def test_endpoints_exist_in_the_engine_api():
    """The paths the dashboard calls are the ones sentinel/api.py serves."""
    from sentinel.api import create_app
    paths = set(create_app().openapi()["paths"])
    for path in ("/health", "/api/metrics", "/api/incidents",
                 "/api/incidents/{incident_id}", "/api/incidents/{incident_id}/contain",
                 "/api/incidents/{incident_id}/status", "/api/firewall/rules",
                 "/api/firewall/rules/{ip}"):
        assert path in paths


def test_dashboard_never_imports_sentinel():
    for path in (ROOT / "dashboard").glob("*.py"):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            else:
                continue
            assert not any(n == "sentinel" or n.startswith("sentinel.") for n in names), path


# -------------------------------------------------------------- KPIs

def test_kpis_formatting():
    values = dict(d.kpis(metrics_doc()))
    assert values == {
        "Events ingested": "1,234",
        "Events / sec": "15.0/s",       # mean of the two complete buckets
        "Open incidents": "3",
        "Blocked IPs": "2",
        "Mean MTTD": "0.42 ms",
        "Mean MTTR": "1,520 ms",
    }


@pytest.mark.parametrize("metrics", [None, {}])
def test_kpis_without_samples_show_na(metrics):
    assert all(value == "n/a" for _, value in d.kpis(metrics))


def test_kpis_zero_counts_are_not_na_but_empty_aggregates_are():
    m = metrics_doc(events_ingested=0, mttd={"count": 0, "mean_ms": None},
                    mttr={"count": 0, "mean_ms": None},
                    incidents_by_status={"open": 0}, firewall={"active_rules": 0})
    values = dict(d.kpis(m))
    assert values["Events ingested"] == "0"
    assert values["Open incidents"] == "0"
    assert values["Blocked IPs"] == "0"
    assert values["Events / sec"] == "n/a"
    assert values["Mean MTTD"] == "n/a" and values["Mean MTTR"] == "n/a"


def test_formatters_reject_non_numbers():
    assert d.fmt_int(True) == "n/a"
    assert d.fmt_ms("12") == "n/a"
    assert d.fmt_rate(None) == "n/a"
    assert d.fmt_ms(0) == "0.00 ms"


# -------------------------------------------------- severity ordering

def test_severity_rank():
    assert [d.severity_rank(s) for s in ("Critical", "High", "Medium", "Low")] == [0, 1, 2, 3]
    assert d.severity_rank("Bogus") == 4 and d.severity_rank(None) == 4


def test_sort_incidents_severity_then_newest():
    items = [incident("Low", 300, inc_id="a"), incident("Critical", 100, inc_id="b"),
             incident("High", 200, inc_id="c"), incident("Critical", 250, inc_id="d")]
    assert [i["id"] for i in d.sort_incidents(items)] == ["d", "b", "c", "a"]


def test_triage_queues_newest_first_and_empty_queues_present():
    items = [incident("High", 1, inc_id="old"), incident("High", 5, inc_id="new"),
             incident("Critical", 3, inc_id="crit", score=None), incident("Weird", 9)]
    queues = d.triage_queues(items)
    assert list(queues) == ["Critical", "High", "Medium", "Low"]
    assert [r["id"] for r in queues["High"]] == ["new", "old"]
    assert queues["Medium"] == [] and queues["Low"] == []
    row = queues["Critical"][0]
    assert row["abuse_score"] == "n/a" and row["mitre"] == "T1110"
    assert queues["High"][0]["abuse_score"] == "90"
    assert d.triage_queues([]) == {s: [] for s in d.SEVERITY_ORDER}


def test_queue_html_escapes_log_derived_values():
    row = d.queue_row(incident())
    row["rule"] = "<script>alert(1)</script>"
    out = d.queue_html([row], "High")
    assert "<script>" not in out and "&lt;script&gt;" in out
    assert "https://attack.mitre.org/techniques/T1110/" in out
    assert "No incidents" in d.queue_html([], "Low")


# ---------------------------------------------------------- chart data

def test_alerts_over_time_buckets_by_minute():
    timeline = [
        {"kind": "alert", "at": "2026-11-09T10:00:05+00:00", "severity": "High"},
        {"kind": "alert", "at": "2026-11-09T10:00:50+00:00", "severity": "High"},
        {"kind": "alert", "at": "2026-11-09T10:01:01+00:00", "severity": "Critical"},
        {"kind": "action", "at": "2026-11-09T10:01:01+00:00"},
        {"kind": "alert", "at": None, "severity": "Low"},
    ]
    rows = d.alerts_over_time([incident(timeline=timeline)])
    assert [(r["time"].minute, r["severity"], r["alerts"]) for r in rows] == [
        (0, "High", 2), (1, "Critical", 1)]
    assert d.alerts_over_time([]) == []


def test_distribution_attackers_and_eps():
    assert d.technique_distribution(metrics_doc())[0] == {"technique": "T1110", "alerts": 5}
    assert d.technique_distribution({}) == []
    top = d.top_attackers([incident(ip="203.0.113.5"), incident(ip="203.0.113.5"),
                           incident(ip="198.51.100.1"), incident(ip="")])
    assert top == [{"src_ip": "203.0.113.5", "alerts": 4},
                   {"src_ip": "198.51.100.1", "alerts": 2}]
    assert [p["eps"] for p in d.eps_series(metrics_doc())] == [10.0, 20.0]
    assert d.eps_series({}) == []


# ----------------------------------------------- detail, audit, firewall

def test_action_timeline_and_audit_log():
    inc = incident(timeline=[
        {"kind": "action", "actor": "soar", "at": "2026-11-09T10:00:00+00:00",
         "name": "block_ip_firewall", "status": "success", "detail": "iptables ..."},
        {"kind": "action", "actor": "analyst", "at": "2026-11-09T10:05:00+00:00",
         "name": "analyst_block_ip", "status": "refused_safety_guard", "detail": "private"},
        {"kind": "status", "actor": "analyst", "at": "2026-11-09T10:06:00+00:00",
         "from": "open", "to": "false_positive", "note": "benign"},
    ])
    inc["actions"] = [{"at": "t", "actor": "soar", "name": "enrich_ip_reputation",
                       "status": "success", "detail": "score 90", "duration_ms": 0.25}]
    assert d.action_timeline(inc)[0]["duration_ms"] == 0.25
    assert d.action_timeline({}) == []
    log = d.audit_log([inc])
    assert [r["action"] for r in log] == ["status change", "analyst_block_ip"]
    assert log[0]["outcome"] == "open -> false_positive"


def test_firewall_table():
    payload = {"rules": [{"ip": "203.0.113.5", "command": "iptables -A INPUT -s 203.0.113.5"
                          " -j DROP", "reason": "r", "created_at_iso": "c",
                          "expires_at_iso": None}]}
    assert d.firewall_table(payload)[0]["expires"] == "never"
    assert d.firewall_table(None) == [] and d.firewall_table({}) == []


@pytest.mark.parametrize("block_status, blocked, level", [
    ("success", True, "success"),
    ("skipped_already_blocked", True, "info"),
    ("refused_safety_guard", False, "warning"),
    ("skipped_no_ip", False, "warning"),
    ("error", False, "error"),
])
def test_describe_contain(block_status, blocked, level):
    res = d.ApiResult(True, 200, {"blocked": blocked,
                                  "block": {"status": block_status, "detail": "why"},
                                  "incident": {"src_ip": "10.0.0.5"}, "sessions": None})
    got_level, message = d.describe_contain(res)
    assert got_level == level and ("10.0.0.5" in message or block_status == "skipped_no_ip")


def test_describe_contain_failed_request():
    level, message = d.describe_contain(d.ApiResult(False, error="engine unreachable"))
    assert level == "error" and "engine unreachable" in message
