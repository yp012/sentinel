import ast
import json
import logging
import threading
import time
from pathlib import Path

import pytest
import requests

from sentinel.intel import AbuseIPDBClient, mock_score
from sentinel.models import Alert
from sentinel.soar import (
    PLAYBOOKS, BlockRefused, FirewallError, FirewallSimulator, PlaybookRunner, SessionManager,
    SOARServices, WebhookDispatcher,
)
from sentinel.soar import firewall as firewall_mod
from tests.factories import settings

SECRET = "sk-test-SUPERSECRET-123"


class FakeResponse:
    def __init__(self, status_code=200, body=None):
        self.status_code = status_code
        self._body = body

    def json(self):
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


class FakeHTTP:
    """Stands in for ``requests``: returns queued responses or raises queued exceptions."""

    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = []

    def _next(self, method, url, **kw):
        self.calls.append((method, url, kw))
        item = self.responses.pop(0) if self.responses else FakeResponse(500)
        if isinstance(item, Exception):
            raise item
        return item

    def get(self, url, **kw):
        return self._next("GET", url, **kw)

    def post(self, url, **kw):
        return self._next("POST", url, **kw)


class Clock:
    def __init__(self, now=1_800_000_000.0):
        self.now = now

    def __call__(self):
        return self.now


def abuse_body(score=42):
    return {"data": {"abuseConfidenceScore": score, "countryCode": "NL",
                     "isp": "Example BV", "totalReports": 7}}


def make_alert(rule_id="SENTINEL-001", severity="High", ip="203.0.113.7", user="root",
               mitre="T1110.001"):
    return Alert(rule_id=rule_id, title=f"{rule_id} test", mitre_technique=mitre,
                 severity=severity, src_ip=ip, user=user, detected_at_ns=time.monotonic_ns())


@pytest.fixture
def services(tmp_path):
    s = settings(abuseipdb_api_key="", webhook_url="", data_dir=str(tmp_path),
                 real_firewall=False)
    return SOARServices(
        settings=s,
        intel=AbuseIPDBClient(s),
        firewall=FirewallSimulator(s),
        sessions=SessionManager(),
        webhook=WebhookDispatcher(s, backoff_s=0),
    )


# ------------------------------------------------------------------- intel: mock

def test_mock_intel_is_deterministic_and_labeled():
    client = AbuseIPDBClient(settings(abuseipdb_api_key=""))
    assert client.mode == "mock"
    a, b = client.score("8.8.4.4"), client.score("8.8.4.4")
    assert a == b
    assert a.source == "mock"
    assert 0 <= a.score <= 60


@pytest.mark.parametrize("ip", ["10.1.2.3", "172.16.0.9", "192.168.1.1", "127.0.0.1", "::1"])
def test_mock_intel_private_and_loopback_score_zero(ip):
    assert mock_score(ip).score == 0


def test_mock_intel_documentation_ranges_are_known_bad():
    for prefix in ("203.0.113", "198.51.100"):
        scores = [mock_score(f"{prefix}.{i}").score for i in range(256)]
        assert min(scores) >= 85 and max(scores) <= 100


def test_mock_intel_other_public_ips_stay_below_block_score():
    scores = [mock_score(f"45.33.{i}.{i}").score for i in range(200)]
    assert max(scores) <= 60
    assert len(set(scores)) > 10  # actually derived from the IP, not constant


def test_intel_rejects_non_ip():
    with pytest.raises(ValueError):
        AbuseIPDBClient(settings(abuseipdb_api_key="")).score("not-an-ip")


# ------------------------------------------------------------------- intel: live

def test_live_intel_parses_and_caches_with_ttl():
    http = FakeHTTP(FakeResponse(200, abuse_body(42)), FakeResponse(200, abuse_body(90)))
    clock = Clock(0)
    client = AbuseIPDBClient(settings(abuseipdb_cache_ttl_s=3600), api_key=SECRET,
                             session=http, clock=clock)
    first = client.score("45.33.32.156")
    assert (first.score, first.source, first.country, first.reports) == (42, "live", "NL", 7)
    method, url, kw = http.calls[0]
    assert url == "https://api.abuseipdb.com/api/v2/check"
    assert kw["headers"]["Key"] == SECRET
    assert kw["timeout"] == 3.0
    assert kw["params"]["ipAddress"] == "45.33.32.156"

    clock.now = 3599
    cached = client.score("45.33.32.156")
    assert (cached.score, cached.source) == (42, "cache")
    assert len(http.calls) == 1

    clock.now = 3601
    assert client.score("45.33.32.156").score == 90
    assert len(http.calls) == 2


def test_live_intel_retries_once_then_degrades_to_mock_without_leaking_key(caplog):
    http = FakeHTTP(requests.ConnectionError(f"boom {SECRET}"), requests.Timeout("slow"))
    client = AbuseIPDBClient(settings(), api_key=SECRET, session=http)
    with caplog.at_level(logging.DEBUG):
        result = client.score("203.0.113.9")
    assert len(http.calls) == 2  # 1 try + 1 retry
    assert result.source == "mock"
    assert result.score >= 85
    assert SECRET not in caplog.text
    assert SECRET not in repr(client)
    assert SECRET not in repr(client.settings)


@pytest.mark.parametrize("response", [
    FakeResponse(429, {}), FakeResponse(200, {"oops": 1}), FakeResponse(200, ValueError("json")),
])
def test_live_intel_bad_responses_degrade(response):
    client = AbuseIPDBClient(settings(), api_key=SECRET, session=FakeHTTP(response, response))
    assert client.score("8.8.8.8").source == "mock"


def test_live_intel_failure_is_not_cached():
    http = FakeHTTP(FakeResponse(500), FakeResponse(500), FakeResponse(200, abuse_body(12)))
    client = AbuseIPDBClient(settings(), api_key=SECRET, session=http)
    assert client.score("8.8.8.8").source == "mock"
    assert client.score("8.8.8.8").source == "live"


# --------------------------------------------------------------------- firewall

def fw(tmp_path, clock=None, **overrides):
    overrides.setdefault("real_firewall", False)
    s = settings(data_dir=str(tmp_path), **overrides)
    return FirewallSimulator(s, clock=clock or Clock())


def test_firewall_block_renders_and_persists(tmp_path):
    f = fw(tmp_path)
    rule = f.block("203.0.113.7", "test", ttl=600)
    assert rule.command == "iptables -I INPUT -s 203.0.113.7 -j DROP"
    assert f.is_blocked("203.0.113.7")
    assert [r.ip for r in f.list_rules()] == ["203.0.113.7"]
    assert f.commands == [rule.command]

    state = json.loads((tmp_path / "firewall_rules.json").read_text())
    assert state["rules"][0]["ip"] == "203.0.113.7"
    log = (tmp_path / "firewall_commands.log").read_text()
    assert "iptables -I INPUT -s 203.0.113.7 -j DROP" in log

    reloaded = fw(tmp_path)
    assert reloaded.is_blocked("203.0.113.7")


def test_firewall_ipv6_uses_ip6tables(tmp_path):
    assert fw(tmp_path).block("2001:db8::66", "x").command == \
        "ip6tables -I INPUT -s 2001:db8::66 -j DROP"


@pytest.mark.parametrize("ip", [
    "10.0.0.1", "172.20.1.1", "192.168.1.1", "127.0.0.1", "::1", "fe80::1",
    "169.254.1.1", "0.0.0.0", "224.0.0.1", "100.64.1.1", "8.8.8.8", "8.8.4.200",
    "1.2.3.4; rm -rf /", " 1.2.3.4", "", "not-an-ip",
])
def test_firewall_safety_guard_refuses(tmp_path, ip):
    f = fw(tmp_path, firewall_allowlist=("8.8.8.8", "8.8.4.0/24"))
    with pytest.raises(BlockRefused):
        f.block(ip, "test")
    assert f.list_rules() == []
    assert f.commands == []


def test_firewall_ttl_expiry(tmp_path):
    clock = Clock()
    f = fw(tmp_path, clock=clock)
    f.block("203.0.113.7", "ttl", ttl=10)
    clock.now += 9.9
    assert f.is_blocked("203.0.113.7")
    clock.now += 0.2
    assert not f.is_blocked("203.0.113.7")
    assert f.commands[-1] == "iptables -D INPUT -s 203.0.113.7 -j DROP"
    assert json.loads((tmp_path / "firewall_rules.json").read_text())["rules"] == []
    # After expiry the IP can be blocked again (a new rule, not the stale one).
    _, created = f.block_with_status("203.0.113.7", "again", ttl=10)
    assert created


def test_firewall_block_is_idempotent(tmp_path):
    f = fw(tmp_path)
    first, created1 = f.block_with_status("203.0.113.7", "first")
    second, created2 = f.block_with_status("203.0.113.7", "second")
    assert (created1, created2) == (True, False)
    assert second is first
    assert second.reason == "first"
    assert len(f.list_rules()) == 1
    assert f.commands == ["iptables -I INPUT -s 203.0.113.7 -j DROP"]
    assert f.block("203.0.113.7", "third") is first


def test_firewall_concurrent_blocks_create_one_rule(tmp_path):
    f = fw(tmp_path)
    created = []
    barrier = threading.Barrier(16)

    def worker():
        barrier.wait()
        created.append(f.block_with_status("198.51.100.4", "race")[1])

    threads = [threading.Thread(target=worker) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert created.count(True) == 1
    assert f.commands == ["iptables -I INPUT -s 198.51.100.4 -j DROP"]


def test_firewall_unblock(tmp_path):
    f = fw(tmp_path)
    f.block("203.0.113.7", "x")
    assert f.unblock("203.0.113.7") is True
    assert f.unblock("203.0.113.7") is False
    assert not f.is_blocked("203.0.113.7")
    assert f.commands[-1] == "iptables -D INPUT -s 203.0.113.7 -j DROP"


def test_firewall_real_mode_uses_list_argv(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(firewall_mod.subprocess, "run",
                        lambda argv, **kw: calls.append((argv, kw)))
    f = fw(tmp_path, real_firewall=True)
    assert f.real
    f.block("203.0.113.7", "x")
    argv, kw = calls[0]
    assert argv == ["iptables", "-I", "INPUT", "-s", "203.0.113.7", "-j", "DROP"]
    assert "shell" not in kw


def test_firewall_real_mode_failure_does_not_record_rule(tmp_path, monkeypatch):
    def fail(argv, **kw):
        raise FileNotFoundError("iptables")
    monkeypatch.setattr(firewall_mod.subprocess, "run", fail)
    f = fw(tmp_path, real_firewall=True)
    with pytest.raises(FirewallError):
        f.block("203.0.113.7", "x")
    assert not f.is_blocked("203.0.113.7")


def test_firewall_simulated_never_shells_out(tmp_path, monkeypatch):
    def forbidden(*a, **kw):
        raise AssertionError("subprocess used in simulated mode")
    monkeypatch.setattr(firewall_mod.subprocess, "run", forbidden)
    f = fw(tmp_path)
    f.block("203.0.113.7", "x", ttl=1)
    f.unblock("203.0.113.7")


def test_firewall_corrupt_state_file_is_ignored(tmp_path):
    (tmp_path / "firewall_rules.json").write_text("{not json")
    assert fw(tmp_path).list_rules() == []


# --------------------------------------------------------------------- sessions

def test_sessions_seeded_and_revocation_is_idempotent():
    sm = SessionManager()
    assert len(sm.active_sessions(user="alice")) == 2
    revoked = sm.revoke_user("alice", "test")
    assert len(revoked) == 2 and all(not s.active for s in revoked)
    assert sm.revoke_user("alice") == []
    assert sm.was_revoked(user="alice")
    assert len(sm.revoke_ip("10.0.2.22")) == 1
    assert sm.active_sessions(user="bob") == []


# ---------------------------------------------------------------------- webhook

def test_webhook_outbox_fallback_when_url_unset(tmp_path):
    outbox = tmp_path / "out" / "outbox.jsonl"
    wh = WebhookDispatcher(settings(webhook_url=""), outbox_path=str(outbox))
    alert = make_alert()
    result = wh.dispatch(alert, {"score": 99}, [{"name": "x"}])
    assert result.channel == "outbox"
    wh.dispatch(alert)
    lines = outbox.read_text().splitlines()
    assert len(lines) == 2
    doc = json.loads(lines[0])
    assert set(doc) == {"schema_version", "alert", "intel", "actions_taken", "timestamp"}
    assert doc["schema_version"] == "1.0"
    assert doc["alert"]["id"] == alert.id
    assert doc["intel"] == {"score": 99}
    assert doc["actions_taken"] == [{"name": "x"}]


def test_webhook_posts_json_with_timeout(tmp_path):
    http = FakeHTTP(FakeResponse(204))
    wh = WebhookDispatcher(settings(), url="https://hooks.example.test/x",
                           outbox_path=str(tmp_path / "o.jsonl"), session=http, backoff_s=0)
    assert wh.dispatch(make_alert()).channel == "webhook"
    method, url, kw = http.calls[0]
    assert (method, url) == ("POST", "https://hooks.example.test/x")
    assert kw["timeout"] == 3.0
    assert kw["json"]["schema_version"] == "1.0"
    assert not (tmp_path / "o.jsonl").exists()


def test_webhook_retries_then_falls_back_to_outbox(tmp_path):
    http = FakeHTTP(requests.ConnectionError("down"), FakeResponse(503))
    wh = WebhookDispatcher(settings(webhook_retries=1), url="https://hooks.example.test/x",
                           outbox_path=str(tmp_path / "o.jsonl"), session=http, backoff_s=0)
    assert wh.dispatch(make_alert()).channel == "outbox"
    assert len(http.calls) == 2
    assert len((tmp_path / "o.jsonl").read_text().splitlines()) == 1


def test_webhook_never_raises(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("")
    wh = WebhookDispatcher(settings(webhook_url=""), outbox_path=str(blocker / "o.jsonl"))
    assert wh.dispatch(make_alert()).channel == "failed"


def test_webhook_rejects_non_http_scheme(tmp_path):
    wh = WebhookDispatcher(settings(), url="file:///etc/passwd",
                           outbox_path=str(tmp_path / "o.jsonl"))
    assert wh.url == ""
    assert wh.dispatch(make_alert()).channel == "outbox"


# -------------------------------------------------------------------- playbooks

def test_playbook_registry_and_chains_are_consistent():
    assert len(PLAYBOOKS) >= 5
    assert {"enrich_ip_reputation", "block_ip_firewall", "revoke_user_sessions",
            "dispatch_webhook_alert", "escalate_critical"} <= set(PLAYBOOKS)
    for rule, chain in settings().playbook_chains.items():
        assert set(chain) <= set(PLAYBOOKS), rule


def test_chain_bruteforce_blocks_and_measures_mttr(services, tmp_path):
    runner = PlaybookRunner(services)
    alert = make_alert(severity="High")
    resp = runner.run(alert)
    assert [a.name for a in resp.actions] == [
        "enrich_ip_reputation", "block_ip_firewall", "escalate_critical",
        "dispatch_webhook_alert",
    ]
    status = {a.name: a.status for a in resp.actions}
    assert status == {
        "enrich_ip_reputation": "success",
        "block_ip_firewall": "success",
        "escalate_critical": "skipped_not_critical",
        "dispatch_webhook_alert": "outbox",
    }
    assert resp.intel.source == "mock" and resp.intel.score >= 85
    assert resp.priority == "P2"
    block = resp.action("block_ip_firewall")
    assert resp.mttr_ns == block.finished_ns - alert.detected_at_ns
    assert resp.mttr_ns > 0
    assert services.firewall.is_blocked("203.0.113.7")
    for a in resp.actions:
        assert a.started_ns <= a.finished_ns

    outbox = json.loads((tmp_path / "webhook_outbox.jsonl").read_text().splitlines()[0])
    assert [a["name"] for a in outbox["actions_taken"]] == [
        "enrich_ip_reputation", "block_ip_firewall", "escalate_critical",
    ]
    assert outbox["intel"]["source"] == "mock"


def test_chain_repeat_alert_same_ip_high_then_critical(services):
    runner = PlaybookRunner(services)
    first = runner.run(make_alert(severity="High"))
    second = runner.run(make_alert(severity="Critical"))

    assert first.action("block_ip_firewall").status == "success"
    block2 = second.action("block_ip_firewall")
    assert block2.status == "skipped_already_blocked"
    assert block2.data["command"] == "iptables -I INPUT -s 203.0.113.7 -j DROP"
    assert second.mttr_ns is None
    assert services.firewall.commands == ["iptables -I INPUT -s 203.0.113.7 -j DROP"]
    assert len(services.firewall.list_rules()) == 1

    esc = second.action("escalate_critical")
    assert esc.status == "success"
    assert second.priority == "P1"
    assert "needs-analyst" in second.tags


def test_chain_identity_repeat_alert_does_not_double_revoke(services):
    runner = PlaybookRunner(services)
    services.sessions.add_session("alice", "203.0.113.50", "vpn")
    alert = dict(rule_id="SENTINEL-006", severity="Critical", ip="203.0.113.50",
                 user="alice", mitre="T1078")
    first = runner.run(make_alert(**alert))
    second = runner.run(make_alert(**alert))

    rv1, rv2 = first.action("revoke_user_sessions"), second.action("revoke_user_sessions")
    assert rv1.status == "success"
    assert len(rv1.data["sessions"]) == 3  # 2 seeded alice sessions + the attacker's
    assert rv2.status == "skipped_already_revoked"
    assert second.action("block_ip_firewall").status == "skipped_already_blocked"
    assert services.sessions.active_sessions(user="alice") == []


def test_chain_revoke_skipped_for_non_t1078(services):
    resp = PlaybookRunner(services, chains={"default": ("revoke_user_sessions",)}).run(
        make_alert(mitre="T1190"))
    assert resp.action("revoke_user_sessions").status == "skipped_not_applicable"
    assert services.sessions.active_sessions(user="root")


def test_block_decision_uses_score_or_severity(services):
    runner = PlaybookRunner(services)
    # Medium + benign public IP (mock score <= 60): no block.
    low = runner.run(make_alert(rule_id="SENTINEL-003", severity="Medium", ip="45.33.32.156",
                                mitre="T1190"))
    assert low.action("block_ip_firewall").status == "skipped_below_threshold"
    # Medium + known-bad IP (mock score >= 85): block on reputation alone.
    bad = runner.run(make_alert(rule_id="SENTINEL-003", severity="Medium", ip="198.51.100.3",
                                mitre="T1190"))
    assert bad.action("block_ip_firewall").status == "success"


def test_block_safety_guard_in_chain_continues(services):
    resp = PlaybookRunner(services).run(make_alert(severity="Critical", ip="10.0.5.10"))
    assert resp.action("block_ip_firewall").status == "refused_safety_guard"
    assert resp.action("dispatch_webhook_alert").status == "outbox"
    assert services.firewall.commands == []


def test_chain_tolerates_failing_and_unknown_playbooks(services, monkeypatch, caplog):
    def boom(ctx):
        raise RuntimeError("kaboom")
    monkeypatch.setitem(PLAYBOOKS, "boom", boom)
    runner = PlaybookRunner(services, chains={
        "default": ("boom", "does_not_exist", "block_ip_firewall")})
    with caplog.at_level(logging.ERROR):
        resp = runner.run(make_alert(rule_id="SENTINEL-999"))
    assert [(a.name, a.status) for a in resp.actions] == [
        ("boom", "error"), ("does_not_exist", "error"), ("block_ip_firewall", "success"),
    ]
    assert "kaboom" in caplog.text


def test_alert_without_ip(services):
    resp = PlaybookRunner(services).run(make_alert(rule_id="SENTINEL-005", ip="",
                                                   user="alice", mitre="T1078",
                                                   severity="Critical"))
    assert resp.action("enrich_ip_reputation").status == "skipped_no_ip"
    assert resp.action("block_ip_firewall").status == "skipped_no_ip"
    assert resp.action("revoke_user_sessions").status == "success"


def test_playbook_names_must_be_unique():
    from sentinel.soar import playbook
    with pytest.raises(ValueError):
        playbook("block_ip_firewall")(lambda ctx: None)


def test_intel_and_soar_never_read_label():
    root = Path(__file__).resolve().parents[1] / "sentinel"
    for pkg in ("intel", "soar"):
        for path in (root / pkg).glob("*.py"):
            for node in ast.walk(ast.parse(path.read_text())):
                assert not (isinstance(node, ast.Attribute) and node.attr == "label"), path
                assert not (isinstance(node, ast.Constant) and node.value == "label"), path
