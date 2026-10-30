import logging
import time

import pytest
from fastapi.testclient import TestClient

from sentinel.api import API_KEY_HEADER, create_app
from sentinel.pipeline import Pipeline
from tests.factories import settings
from tests.test_pipeline import ATTACKER, ssh_fail

KEY = "test-key-Zq8!x"


def make_client(tmp_path, *, api_key="", max_body_bytes=None, **overrides):
    s = settings(abuseipdb_api_key="", webhook_url="", api_key=api_key, log_paths=(),
                 **overrides)
    pipe = Pipeline(s, data_dir=str(tmp_path), db_path=str(tmp_path / "incidents.db"))
    app = create_app(pipe, max_body_bytes=max_body_bytes)
    return TestClient(app), pipe


@pytest.fixture
def client(tmp_path):
    c, pipe = make_client(tmp_path)
    with c:
        yield c
    pipe.close()


def attack(client, n, ip=ATTACKER, user="root"):
    resp = client.post("/ingest", json={"lines": [ssh_fail(i, ip, user) for i in range(n)]})
    assert resp.status_code == 200, resp.text
    return resp.json()


# ----------------------------------------------------------------- flows

def test_ingest_incident_contain_flow(client):
    body = attack(client, 6)
    assert body["parsed"] == 6 and body["alerts"] == 1 and body["errors"] == []
    [inc_id] = body["incidents"]

    inc = client.get(f"/api/incidents/{inc_id}").json()
    assert inc["rule_id"] == "SENTINEL-001"
    assert inc["severity"] == "High"
    assert inc["src_ip"] == ATTACKER
    assert inc["intel"]["score"] >= 85                     # mock intel: known-bad range
    assert inc["status"] == "contained"                    # auto-blocked by the playbook
    assert [a["name"] for a in inc["actions"]] == [
        "enrich_ip_reputation", "block_ip_firewall", "escalate_critical",
        "dispatch_webhook_alert"]
    assert inc["mttd_ms"] is not None and inc["mttr_ms"] is not None

    rules = client.get("/api/firewall/rules").json()
    assert [r["ip"] for r in rules["rules"]] == [ATTACKER]

    # Analyst lifts the block, then re-contains with one click.
    assert client.delete(f"/api/firewall/rules/{ATTACKER}").json() == {
        "ip": ATTACKER, "removed": True}
    assert client.delete(f"/api/firewall/rules/{ATTACKER}").status_code == 404
    resp = client.post(f"/api/incidents/{inc_id}/contain", json={"note": "confirmed"})
    assert resp.status_code == 200
    result = resp.json()
    assert result["blocked"] is True
    assert result["block"]["status"] == "success"
    assert result["contained"] is True
    analyst = [e for e in result["incident"]["timeline"] if e.get("actor") == "analyst"]
    assert [e["kind"] for e in analyst] == ["note", "action", "action"]
    assert analyst[0]["note"] == "confirmed"
    assert client.get("/api/firewall/rules").json()["count"] == 1

    # Containing again is idempotent and still reports the existing rule.
    again = client.post(f"/api/incidents/{inc_id}/contain").json()
    assert again["block"]["status"] == "skipped_already_blocked"
    assert again["blocked"] is True

    done = client.post(f"/api/incidents/{inc_id}/status",
                       json={"status": "resolved", "note": "closed"}).json()
    assert done["status"] == "resolved" and done["resolved_at"] is not None
    assert client.get("/api/incidents", params={"status": "resolved"}).json()["count"] == 1
    assert client.get("/api/incidents", params={"status": "open"}).json()["count"] == 0


def test_contain_reports_safety_guard_refusal(client):
    # root has a seeded session from 10.0.5.10 (internal): block refused, sessions revoked.
    [inc_id] = attack(client, 6, ip="10.0.5.10")["incidents"]
    assert client.get(f"/api/incidents/{inc_id}").json()["status"] == "open"

    result = client.post(f"/api/incidents/{inc_id}/contain").json()
    assert result["blocked"] is False
    assert result["block"]["status"] == "refused_safety_guard"
    assert "never blocked" in result["block"]["detail"]
    assert result["sessions"]["status"] == "success"
    assert result["contained"] is True
    assert client.get("/api/firewall/rules").json()["count"] == 0


def test_repeat_alert_merges_into_one_incident(client):
    body = attack(client, 25)  # High at 6 failures, Critical escalation at 20
    assert body["alerts"] == 2
    assert len(body["incidents"]) == 1

    listing = client.get("/api/incidents").json()
    assert listing["count"] == 1
    inc = listing["incidents"][0]
    assert inc["severity"] == "Critical"
    assert inc["alert_count"] == 2
    assert inc["priority"] == "P1"
    assert "escalated" in inc["tags"]
    assert {"kind": "severity", "from": "High", "to": "Critical"}.items() <= next(
        e for e in inc["timeline"] if e["kind"] == "severity").items()
    blocks = [a["status"] for a in inc["actions"] if a["name"] == "block_ip_firewall"]
    assert blocks == ["success", "skipped_already_blocked"]
    assert len(inc["actions"]) == 8  # both chains appended to one timeline

    assert client.get("/api/incidents", params={"severity": "Critical"}).json()["count"] == 1
    assert client.get("/api/incidents", params={"severity": "High"}).json()["count"] == 0
    m = client.get("/api/metrics").json()
    assert m["alerts_by_severity"]["High"] == 1 and m["alerts_by_severity"]["Critical"] == 1
    assert m["incidents_total"] == 1
    assert m["mttd"]["count"] == 2 and m["mttr"]["count"] == 1
    assert m["firewall"] == {"active_rules": 1, "real": False}
    assert m["intel_mode"] == "mock"


def test_single_line_ingest_and_unparsed(client):
    body = client.post("/ingest", json={"line": "garbage"}).json()
    assert body == {"received": 1, "parsed": 0, "unparsed": 1, "alerts": 0,
                    "incidents": [], "errors": []}
    assert client.post("/ingest", json={"line": ssh_fail(0)}).json()["parsed"] == 1


def test_catalog_endpoints(client):
    rules = client.get("/api/rules").json()["rules"]
    ssh = next(r for r in rules if r["id"] == "SENTINEL-001")
    assert ssh["mitre"] == "T1110.001"
    assert ssh["mitre_url"] == "https://attack.mitre.org/techniques/T1110/001/"
    assert "block_ip_firewall" in ssh["playbooks"]
    pbs = client.get("/api/playbooks").json()
    names = {p["name"] for p in pbs["playbooks"]}
    assert {"enrich_ip_reputation", "block_ip_firewall", "revoke_user_sessions"} <= names
    assert all(p["description"] for p in pbs["playbooks"])


def test_health(client):
    assert client.get("/health").json() == {"status": "ok", "tailing": False,
                                            "auth_required": False}


def test_bad_incident_ids(client):
    assert client.get("/api/incidents/INC-000000000000").status_code == 404
    assert client.post("/api/incidents/INC-000000000000/contain").status_code == 404
    assert client.get("/api/incidents/../../etc").status_code == 404
    assert client.get("/api/incidents/not-an-id").status_code == 422
    assert client.delete("/api/firewall/rules/not-an-ip").status_code == 422


# ------------------------------------------------------------------ auth

def test_auth_required_when_key_set(tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    c, pipe = make_client(tmp_path, api_key=KEY)
    with c:
        assert c.get("/health").status_code == 200
        assert c.get("/health").json()["auth_required"] is True
        assert c.get("/api/metrics").status_code == 401
        assert c.get("/api/metrics", headers={API_KEY_HEADER: "wrong"}).status_code == 401
        assert c.get("/api/metrics", headers={API_KEY_HEADER: KEY[:-1]}).status_code == 401
        assert c.post("/ingest", json={"line": "x"}).status_code == 401
        assert c.get("/api/metrics", headers={API_KEY_HEADER: KEY}).status_code == 200
        ok = c.post("/ingest", json={"line": ssh_fail(0)}, headers={API_KEY_HEADER: KEY})
        assert ok.status_code == 200
    pipe.close()
    assert KEY not in caplog.text
    assert KEY not in repr(pipe.settings)


def test_no_auth_when_key_unset(client):
    assert client.get("/api/metrics").status_code == 200
    assert client.get("/api/metrics", headers={API_KEY_HEADER: "anything"}).status_code == 200


# ------------------------------------------------------- limits/validation

def test_body_size_limit(tmp_path):
    c, pipe = make_client(tmp_path, max_body_bytes=1024)
    with c:
        big = {"lines": ["x" * 100] * 20}
        assert c.post("/ingest", json=big).status_code == 413

        def chunks():  # no Content-Length: streamed (chunked) body
            for _ in range(20):
                yield b"x" * 100

        resp = c.post("/ingest", content=chunks(), headers={"content-type": "application/json"})
        assert resp.status_code == 413
        assert c.post("/ingest", json={"line": ssh_fail(0)}).status_code == 200
    assert pipe.store.metrics()["lines_received"] == 1
    pipe.close()


def test_line_count_and_length_limits(tmp_path):
    c, pipe = make_client(tmp_path, ingest_max_lines=3, ingest_max_line_chars=50)
    with c:
        assert c.post("/ingest", json={"lines": ["a"] * 4}).status_code == 422
        assert c.post("/ingest", json={"line": "a" * 51}).status_code == 422
        assert c.post("/ingest", json={"lines": ["a"] * 3}).status_code == 200
    pipe.close()


@pytest.mark.parametrize("payload", [
    {},
    {"line": 5},
    {"lines": "not-a-list"},
    {"lines": ["ok", 7]},
    {"line": "a", "lines": ["b"]},
    {"line": "a", "extra": True},
])
def test_ingest_strict_validation(client, payload):
    assert client.post("/ingest", json=payload).status_code == 422


def test_status_validation(client):
    [inc_id] = attack(client, 6)["incidents"]
    url = f"/api/incidents/{inc_id}/status"
    assert client.post(url, json={"status": "deleted"}).status_code == 422
    assert client.post(url, json={"status": "open", "who": "x"}).status_code == 422
    assert client.post(url, json={"status": "open", "note": "n" * 1001}).status_code == 422
    assert client.post(url, json={"status": "false_positive"}).status_code == 200
    assert client.get("/api/incidents", params={"severity": "Huge"}).status_code == 422
    assert client.get("/api/incidents", params={"limit": 0}).status_code == 422


# -------------------------------------------------------------- lifecycle

def test_startup_tails_log_paths_and_shutdown_stops(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("")
    s = settings(abuseipdb_api_key="", webhook_url="", api_key="", log_paths=(str(log),),
                 tail_poll_interval_s=0.01)
    pipe = Pipeline(s, data_dir=str(tmp_path))
    with TestClient(create_app(pipe)) as c:
        assert c.get("/health").json()["tailing"] is True
        with log.open("a") as fh:
            fh.write("".join(ssh_fail(i) + "\n" for i in range(6)))
        deadline = time.monotonic() + 5
        while (c.get("/api/metrics").json()["incidents_total"] < 1
               and time.monotonic() < deadline):
            time.sleep(0.02)
        assert c.get("/api/incidents").json()["count"] == 1
    assert not pipe.tailing
    pipe.close()
