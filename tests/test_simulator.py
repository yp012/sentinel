import ipaddress
import json
import re
import threading
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

import pytest
import requests

from sentinel.config import Settings
from sentinel.parsers import parse_any
from simulator import simulate as sim
from tests.test_pipeline import make_pipeline

START = datetime(2026, 10, 27, 9, 0, 0, tzinfo=timezone.utc)
LABELS = {"benign", "T1110", "T1190", "T1078"}
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DEFAULTS = Settings()


def ips_in(line: str) -> list[ipaddress.IPv4Address]:
    return [ipaddress.ip_address(m) for m in IPV4.findall(line)]


def is_attacker_ip(ip) -> bool:
    return any(ipaddress.ip_address(ip) in net for net in sim.ATTACKER_NETS)


# ------------------------------------------------------------- determinism

def test_same_seed_same_output():
    assert sim.generate_mixed(400, 0.3, 7, START) == sim.generate_mixed(400, 0.3, 7, START)
    assert sim.generate_benign(200, 7, START) == sim.generate_benign(200, 7, START)
    for kind in sim.ATTACK_KINDS:
        assert (sim.generate_attack_campaign(kind, 7, START)
                == sim.generate_attack_campaign(kind, 7, START))


def test_different_seed_different_output():
    assert sim.generate_mixed(400, 0.3, 7, START) != sim.generate_mixed(400, 0.3, 8, START)


def test_timestamps_follow_start_and_lines_are_sorted():
    later = START + timedelta(days=3)
    lines = sim.generate_mixed(300, 0.2, 1, later)
    assert [ln.ts for ln in lines] == sorted(ln.ts for ln in lines)
    benign = [ln for ln in lines if ln.label == "benign"]
    assert benign[0].ts >= later
    assert all(ln.ts.tzinfo is not None for ln in lines)


def test_mixed_respects_size_and_ratio():
    lines = sim.generate_mixed(1000, 0.2, 3, START)
    assert len(lines) == 1000
    attack = sum(ln.label != "benign" for ln in lines)
    assert 0.2 <= attack / len(lines) < 0.3   # one campaign of overshoot at most


def test_unknown_kind_rejected():
    with pytest.raises(ValueError):
        sim.generate_attack_campaign("ddos", 1, START)


# ------------------------------------------------------------------ labels

def test_every_line_is_labelled_and_parses():
    lines = sim.generate_mixed(800, 0.3, 11, START)
    kinds = set()
    for ln in lines:
        assert ln.label in LABELS
        assert (ln.label == "benign") == (ln.campaign_id is None)
        if ln.campaign_id is not None:
            assert ln.campaign_kind in sim.ATTACK_KINDS
            kinds.add(ln.campaign_kind)
        event = parse_any(ln.line)
        assert event is not None, ln.line
        assert event.label is None              # labels never travel inside the line
        # The rendered timestamp is exactly the record's ts.
        assert event.ts == ln.ts, ln.line
    assert kinds == set(sim.ATTACK_KINDS)


@pytest.mark.parametrize("kind,labels", [
    ("ssh_bruteforce", {"T1110"}),
    ("ssh_bruteforce_then_success", {"T1110", "T1078"}),
    ("sqli", {"T1190"}),
    ("path_traversal", {"T1190"}),
    ("credential_stuffing", {"T1110"}),
    ("impossible_travel_vpn", {"T1078"}),
    ("onprem_ssh_no_badge", {"T1078"}),
])
def test_campaign_labels(kind, labels):
    lines = sim.generate_attack_campaign(kind, 5, START)
    assert {ln.label for ln in lines} == labels
    assert len({ln.campaign_id for ln in lines}) == 1


# ---------------------------------------------------------- burst windows

def _attempts(events) -> int:
    """Count SSH attempts the way rule 001 does: an invalid-user pair counts once."""
    pending = set()
    count = 0
    for e in events:
        if e.fields.get("invalid_user"):
            key = (e.user, e.fields["port"])
            if key in pending:
                pending.discard(key)
                continue
            pending.add(key)
        count += 1
    return count


@pytest.mark.parametrize("seed", range(25))
@pytest.mark.parametrize("kind", ["ssh_bruteforce", "ssh_bruteforce_then_success"])
def test_ssh_bruteforce_fits_window(kind, seed):
    events = [parse_any(ln.line) for ln in sim.generate_attack_campaign(kind, seed, START)]
    failures = [e for e in events if e.event_type == "ssh_failed"]
    span = (failures[-1].ts - failures[0].ts).total_seconds()
    assert span < 30 <= DEFAULTS.ssh_bruteforce_window_s
    assert 8 <= _attempts(failures) <= 40
    assert _attempts(failures) > DEFAULTS.ssh_bruteforce_threshold
    assert len({e.src_ip for e in events}) == 1
    successes = [e for e in events if e.event_type == "ssh_success"]
    if kind == "ssh_bruteforce_then_success":
        assert len(successes) == 1
        gap = (successes[0].ts - failures[-1].ts).total_seconds()
        assert 0 < gap < DEFAULTS.success_after_bf_window_s
    else:
        assert successes == []


def test_some_bruteforce_campaigns_use_invalid_user_pairs():
    paired = 0
    for seed in range(20):
        lines = [ln.line for ln in sim.generate_attack_campaign("ssh_bruteforce", seed, START)]
        paired += any("Invalid user" in ln for ln in lines)
    assert 0 < paired < 20


@pytest.mark.parametrize("seed", range(25))
def test_credential_stuffing_fits_window(seed):
    events = [parse_any(ln.line)
              for ln in sim.generate_attack_campaign("credential_stuffing", seed, START)]
    by_ip = defaultdict(list)
    for e in events:
        assert e.event_type in ("http_login_failed", "vpn_login")
        by_ip[e.src_ip].append(e)
    assert len(by_ip) == 2
    for evs in by_ip.values():
        span = (evs[-1].ts - evs[0].ts).total_seconds()
        assert span < DEFAULTS.http_login_fail_window_s
        assert len(evs) > DEFAULTS.http_login_fail_threshold
    vpn = [e for e in events if e.source == "vpn"]
    assert all(e.fields["success"] is False for e in vpn)
    assert len({e.user for e in vpn}) >= DEFAULTS.web_spray_distinct_users


@pytest.mark.parametrize("seed", range(10))
def test_identity_campaign_timing(seed):
    it = [parse_any(ln.line)
          for ln in sim.generate_attack_campaign("impossible_travel_vpn", seed, START)]
    badge_in, vpn = it[0], it[-1]
    assert badge_in.fields["direction"] == "in" and badge_in.fields["granted"]
    assert vpn.fields["success"] is True
    assert 0 < (vpn.ts - badge_in.ts).total_seconds() < DEFAULTS.onsite_window_s

    op = [parse_any(ln.line)
          for ln in sim.generate_attack_campaign("onprem_ssh_no_badge", seed, START)]
    ssh = op[-1]
    badges_in = [e for e in op if e.source == "pacs" and e.fields["direction"] == "in"]
    assert badges_in, "victim must be a known badge holder"
    assert all((ssh.ts - b.ts).total_seconds() > DEFAULTS.badge_lookback_s for b in badges_in)
    assert ipaddress.ip_address(ssh.src_ip).is_private


# -------------------------------------------------------------- IP ranges

def test_attacker_ips_only_from_documentation_ranges():
    lines = sim.generate_mixed(3000, 0.4, 21, START)
    for ln in lines:
        if ln.label == "benign":
            assert not any(is_attacker_ip(ip) for ip in ips_in(ln.line)), ln.line
            continue
        if ln.campaign_kind == "onprem_ssh_no_badge":
            # By definition this one comes from inside the network.
            assert ipaddress.ip_address(ln.actor_ip).is_private
            assert all(ip.is_private for ip in ips_in(ln.line))
            continue
        assert is_attacker_ip(ln.actor_ip), ln
        assert all(is_attacker_ip(ip) for ip in ips_in(ln.line)), ln.line


def test_concurrent_campaigns_get_distinct_actors():
    lines = sim.generate_mixed(3000, 0.4, 21, START)
    owners = defaultdict(set)
    for ln in lines:
        if ln.campaign_id is not None:
            owners[ln.actor_ip].add(ln.campaign_id)
            identity = ("impossible_travel_vpn", "onprem_ssh_no_badge")
            if ln.actor_user and ln.campaign_kind in identity:
                owners["user:" + ln.actor_user].add(ln.campaign_id)
    assert all(len(c) == 1 for c in owners.values())


# ------------------------------------------------- benign shape invariants

def test_benign_users_badge_in_before_vpn_or_ssh():
    lines = sim.generate_benign(4000, 2, START)
    events = [parse_any(ln.line) for ln in lines]
    assert all(e is not None for e in events)
    last_in, onsite = {}, {}
    seen = Counter()
    for e in events:
        if e.source == "pacs" and e.fields["granted"]:
            onsite[e.user] = e.fields["direction"] == "in"
            if onsite[e.user]:
                last_in[e.user] = e.ts
        elif e.source == "vpn" and e.fields["success"]:
            seen["vpn"] += 1
            assert e.user in last_in, "VPN user never badged in"
            assert not onsite[e.user], "benign VPN while badged in"
        elif e.source == "ssh" and e.event_type == "ssh_success":
            seen["ssh"] += 1
            assert onsite.get(e.user), "on-prem SSH without a badge-in"
            assert (e.ts - last_in[e.user]).total_seconds() < DEFAULTS.badge_lookback_s
    assert seen["vpn"] > 0 and seen["ssh"] > 0


def test_benign_failures_stay_inside_thresholds():
    events = [parse_any(ln.line) for ln in sim.generate_benign(6000, 4, START)]
    failures = defaultdict(list)
    for e in events:
        if e.event_type == "ssh_failed":
            failures[("ssh", e.src_ip)].append(e.ts)
        elif e.event_type == "http_login_failed" or (
                e.source == "vpn" and e.fields["success"] is False):
            failures[("login", e.src_ip)].append(e.ts)
    assert failures, "benign traffic should include a few typos"
    window = timedelta(seconds=max(DEFAULTS.ssh_bruteforce_window_s,
                                   DEFAULTS.http_login_fail_window_s))
    for times in failures.values():
        for i, t in enumerate(times):
            in_window = sum(1 for u in times[i:] if u - t <= window)
            assert in_window <= 3


def test_benign_includes_hard_negatives_and_404s():
    lines = [ln.line for ln in sim.generate_benign(3000, 9, START)]
    text = "\n".join(lines)
    assert "select" in text and "union" in text and "drop" in text and "--" in text
    assert any('" 404 ' in ln for ln in lines)


# ------------------------------------------------------------ service mode

class FakeResponse:
    def __init__(self, status_code=200, doc=None):
        self.status_code = status_code
        self._doc = doc if doc is not None else {}

    def json(self):
        return self._doc


@pytest.fixture
def no_network(monkeypatch):
    """Fail loudly if anything reaches the real requests functions."""
    def boom(*a, **kw):
        raise AssertionError("network access attempted")
    monkeypatch.setattr(sim.requests, "get", boom)
    monkeypatch.setattr(sim.requests, "post", boom)
    return monkeypatch


def make_service(**kw):
    cfg = sim.ServiceConfig(engine_url="http://engine.test", seed="t", rate=1e6,
                            attack_ratio=0.3, batch_size=40, summary_interval_s=0.0, **kw)
    return sim.Service(cfg, threading.Event(), out=lambda msg: None)


def test_post_body_contains_only_raw_lines(no_network):
    calls = []

    def fake_post(url, json=None, headers=None, timeout=None):
        calls.append({"url": url, "json": json, "headers": headers, "timeout": timeout})
        return FakeResponse(200, {"alerts": 1})

    no_network.setattr(sim.requests, "post", fake_post)
    svc = make_service(api_key="s3cret")
    lines = sim.generate_mixed(200, 0.5, 13, START)
    assert svc.post(lines)
    (call,) = calls
    assert call["url"] == "http://engine.test/ingest"
    assert call["headers"] == {"X-API-Key": "s3cret"}
    assert call["timeout"]
    assert call["json"] == {"lines": [ln.line for ln in lines]}
    body = json.dumps(call["json"])
    for ln in lines:
        if ln.campaign_id:
            assert ln.campaign_id not in body
    assert not re.search(r'"(?:label|campaign_id|benign|T1110|T1190|T1078)"', body)
    assert "T1110" not in body and "T1190" not in body and "T1078" not in body


def test_no_api_key_header_when_unset(no_network):
    seen = []
    no_network.setattr(sim.requests, "post",
                       lambda url, **kw: seen.append(kw["headers"]) or FakeResponse())
    make_service().post(sim.generate_benign(5, 1, START))
    assert seen == [{}]


def test_service_loop_survives_engine_restart_and_stops(no_network):
    """Health check first, a connection error mid-run (engine restart), then stop."""
    svc = make_service()
    health = iter([FakeResponse(503), FakeResponse(200, {"status": "starting"})]
                  + [FakeResponse(200, {"status": "ok"})] * 100)
    bodies = []

    def fake_get(url, timeout=None):
        assert url == "http://engine.test/health"
        return next(health)

    def fake_post(url, json=None, headers=None, timeout=None):
        if len(bodies) == 2 and not getattr(fake_post, "failed", False):
            fake_post.failed = True
            raise requests.ConnectionError("engine restarting")
        bodies.append(json)
        if len(bodies) >= 6:
            svc.stop.set()
        return FakeResponse(200, {"alerts": 0})

    no_network.setattr(sim.requests, "get", fake_get)
    no_network.setattr(sim.requests, "post", fake_post)
    no_network.setattr(sim.Service, "wait_for_engine", _fast_wait(sim.Service.wait_for_engine))
    assert svc.run() == 0
    assert len(bodies) == 6
    assert svc.http_failures == 1
    assert svc.batches == 6 and svc.posted == sum(len(b["lines"]) for b in bodies)
    # The batch that failed was retried, not lost: nothing was dropped.
    assert svc.dropped == 0
    assert sum(svc.by_label.values()) == svc.posted
    assert set(svc.by_kind) - {"benign"} <= set(sim.ATTACK_KINDS)
    for body in bodies:
        assert set(body) == {"lines"}
        assert all(isinstance(ln, str) for ln in body["lines"])
    assert "posted=" in svc.summary()


def _fast_wait(original):
    """wait_for_engine with its backoff sleeps skipped."""
    def wrapper(self):
        real_wait = self.stop.wait
        self.stop.wait = lambda timeout=None: self.stop.is_set()
        try:
            return original(self)
        finally:
            self.stop.wait = real_wait
    return wrapper


def test_rejected_batch_is_dropped_not_retried(no_network):
    no_network.setattr(sim.requests, "post", lambda url, **kw: FakeResponse(422))
    svc = make_service()
    assert svc.post(sim.generate_benign(10, 1, START)) is False
    assert svc.dropped == 10 and svc.http_failures == 1


def test_run_returns_when_stopped_before_engine_is_up(no_network):
    no_network.setattr(sim.requests, "get",
                       lambda url, **kw: (_ for _ in ()).throw(requests.ConnectionError()))
    svc = make_service()
    svc.stop.set()
    assert svc.run() == 0
    assert svc.posted == 0


def test_config_from_env(monkeypatch):
    monkeypatch.setenv("ENGINE_URL", "http://e:9/")
    monkeypatch.setenv("SIM_SEED", "abc")
    monkeypatch.setenv("SIM_RATE", "5")
    monkeypatch.setenv("SIM_ATTACK_RATIO", "0.25")
    monkeypatch.setenv("SIM_BATCH_SIZE", "7")
    monkeypatch.setenv("SENTINEL_API_KEY", "zz-secret-zz")
    cfg = sim.ServiceConfig.from_env()
    assert (cfg.engine_url, cfg.seed, cfg.rate, cfg.attack_ratio, cfg.batch_size,
            cfg.api_key) == ("http://e:9", "abc", 5.0, 0.25, 7, "zz-secret-zz")
    assert "zz-secret-zz" not in repr(cfg)
    monkeypatch.setenv("SIM_RATE", "0")
    with pytest.raises(ValueError):
        sim.ServiceConfig.from_env()


def test_simulator_does_not_import_sentinel():
    import ast
    tree = ast.parse(open(sim.__file__, encoding="utf-8").read())
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module.split(".")[0])
    assert "sentinel" not in names
    assert names - {"__future__"} <= {
        "ipaddress", "json", "os", "random", "signal", "sys", "threading", "time",
        "collections", "dataclasses", "datetime", "typing", "requests"}


# -------------------------------------------------------- integration

@pytest.mark.parametrize("seed", [101, 202])
def test_mixed_workload_through_real_pipeline(tmp_path, seed):
    lines = sim.generate_mixed(900, 0.3, seed, START)
    pipe = make_pipeline(tmp_path / str(seed))
    try:
        detected = set()
        false_positives = []
        for ln in lines:
            touched = pipe.ingest(ln.line)
            if not touched:
                continue
            if ln.campaign_id is None:
                false_positives.append(ln.line)
            else:
                detected.add(ln.campaign_id)
        campaigns = {ln.campaign_id: ln.campaign_kind for ln in lines if ln.campaign_id}
        assert set(campaigns.values()) == set(sim.ATTACK_KINDS)
        assert false_positives == []
        missed = {cid: kind for cid, kind in campaigns.items() if cid not in detected}
        assert missed == {}
        assert pipe.store.metrics()["lines_unparsed"] == 0
    finally:
        pipe.close()
