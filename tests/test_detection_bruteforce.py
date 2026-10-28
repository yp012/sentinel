import pytest

from sentinel.detection import SSHBruteForce, SuccessAfterBruteForce, WebLoginBruteForce
from tests.factories import (
    http_login_failed, settings, ssh_failed, ssh_success, vpn_login,
)


def feed(detector, events):
    alerts = []
    for ev in events:
        alerts.extend(detector.evaluate(ev))
    return alerts


# ------------------------------------------------------------- SENTINEL-001

def test_ssh_bf_true_positive_six_in_60s():
    det = SSHBruteForce(settings())
    events = [ssh_failed(t=i * 10) for i in range(6)]  # t = 0..50
    alerts = feed(det, events)
    assert len(alerts) == 1
    a = alerts[0]
    assert a.rule_id == "SENTINEL-001"
    assert a.mitre_technique == "T1110.001"
    assert a.severity == "High"
    assert a.src_ip == "203.0.113.7"
    assert a.evidence["failures"] == 6
    assert a.detected_at_ns == events[-1].ingested_ns


def test_ssh_bf_boundary_exactly_five_does_not_fire():
    det = SSHBruteForce(settings())
    assert feed(det, [ssh_failed(t=i) for i in range(5)]) == []


def test_ssh_bf_boundary_six_spread_over_120s_does_not_fire():
    det = SSHBruteForce(settings())
    assert feed(det, [ssh_failed(t=i * 24) for i in range(6)]) == []  # t = 0..120


def test_ssh_bf_window_edge_is_inclusive():
    det = SSHBruteForce(settings())
    times = [0, 12, 24, 36, 48, 60]  # sixth event exactly 60s after the first
    assert len(feed(det, [ssh_failed(t=t) for t in times])) == 1


def test_ssh_bf_benign_mixed_ips_and_successes():
    det = SSHBruteForce(settings())
    events = [ssh_failed(t=i, ip=f"192.0.2.{i}") for i in range(10)]
    events += [ssh_success(t=20 + i) for i in range(10)]
    assert feed(det, events) == []


def test_ssh_bf_cooldown_suppresses_storm_then_refires():
    det = SSHBruteForce(settings(alert_cooldown_s=300))
    first = feed(det, [ssh_failed(t=i) for i in range(10)])
    assert len(first) == 1
    # Same IP keeps going inside the cooldown (but below critical): no new alerts.
    assert feed(det, [ssh_failed(t=100 + i) for i in range(10)]) == []
    # After the cooldown expires a fresh burst alerts again.
    assert len(feed(det, [ssh_failed(t=400 + i) for i in range(6)])) == 1


def test_ssh_bf_critical_at_twenty_escalates_once():
    det = SSHBruteForce(settings())
    alerts = feed(det, [ssh_failed(t=i * 0.5) for i in range(30)])
    assert [a.severity for a in alerts] == ["High", "Critical"]
    assert alerts[1].evidence["failures"] == 20


def test_ssh_bf_invalid_user_double_log_counts_once():
    det = SSHBruteForce(settings())
    events = []
    for i in range(5):  # 5 real attempts, each logged twice by sshd
        user = f"user{i}"
        events.append(ssh_failed(t=i * 5, user=user, reason="invalid_user", invalid=True))
        events.append(ssh_failed(t=i * 5 + 1, user=user, reason="failed_auth", invalid=True))
    assert feed(det, events) == []  # 5 attempts, not 10
    # A sixth attempt (double-logged in reverse order) crosses the threshold.
    alerts = feed(det, [
        ssh_failed(t=30, user="user5", reason="failed_auth", invalid=True),
        ssh_failed(t=30.5, user="user5", reason="invalid_user", invalid=True),
    ])
    assert len(alerts) == 1
    assert alerts[0].evidence["failures"] == 6


def test_ssh_bf_invalid_user_pair_more_than_1s_apart_counts_twice():
    det = SSHBruteForce(settings())
    events = [ssh_failed(t=0, user="x", reason="invalid_user", invalid=True),
              ssh_failed(t=1.5, user="x", reason="failed_auth", invalid=True)]
    events += [ssh_failed(t=2 + i) for i in range(4)]
    assert len(feed(det, events)) == 1


def test_ssh_bf_out_of_order_events_still_counted():
    det = SSHBruteForce(settings())
    times = [50, 10, 40, 0, 30, 20]
    assert len(feed(det, [ssh_failed(t=t) for t in times])) == 1


def test_ssh_bf_memory_capped_per_key_and_keys():
    det = SSHBruteForce(settings(window_max_events_per_key=8, window_max_keys=4))
    feed(det, [ssh_failed(t=i * 0.01) for i in range(100)])
    assert len(det._window.get("203.0.113.7")) == 8
    feed(det, [ssh_failed(t=i, ip=f"192.0.2.{i}") for i in range(20)])
    assert len(det._window) == 4


@pytest.mark.parametrize("threshold,window", [(2, 10), (10, 300)])
def test_ssh_bf_thresholds_come_from_config(threshold, window):
    det = SSHBruteForce(settings(ssh_bruteforce_threshold=threshold,
                                 ssh_bruteforce_window_s=window))
    assert feed(det, [ssh_failed(t=i) for i in range(threshold)]) == []
    assert len(feed(det, [ssh_failed(t=threshold)])) == 1


# ------------------------------------------------------------- SENTINEL-002

def test_web_bf_true_positive_http():
    det = WebLoginBruteForce(settings())
    alerts = feed(det, [http_login_failed(t=i * 10) for i in range(6)])
    assert len(alerts) == 1
    assert alerts[0].rule_id == "SENTINEL-002"
    assert alerts[0].mitre_technique == "T1110.001"
    assert alerts[0].severity == "High"


def test_web_bf_vpn_failures_count_with_http_failures():
    det = WebLoginBruteForce(settings())
    ip = "198.51.100.9"
    events = [http_login_failed(t=i, ip=ip) for i in range(3)]
    events += [vpn_login(t=10 + i, ip=ip, user="alice", success=False) for i in range(3)]
    assert len(feed(det, events)) == 1


def test_web_bf_password_spraying_many_users():
    det = WebLoginBruteForce(settings())
    events = [vpn_login(t=i, ip="198.51.100.30", user=f"u{i}", success=False)
              for i in range(6)]
    alerts = feed(det, events)
    assert len(alerts) == 1
    assert alerts[0].mitre_technique == "T1110.003"
    assert alerts[0].evidence["distinct_users"] == 6


def test_web_bf_benign_successes_and_plain_requests():
    det = WebLoginBruteForce(settings())
    events = [vpn_login(t=i, success=True) for i in range(20)]
    events += [http_login_failed(t=i, ip=f"192.0.2.{i}") for i in range(20)]
    assert feed(det, events) == []


def test_web_bf_boundary_five_no_fire_and_spread_no_fire():
    det = WebLoginBruteForce(settings())
    assert feed(det, [http_login_failed(t=i) for i in range(5)]) == []
    det = WebLoginBruteForce(settings())
    assert feed(det, [http_login_failed(t=i * 24) for i in range(6)]) == []


# ------------------------------------------------------------- SENTINEL-006

def _tripped_detector(**overrides):
    s = settings(**overrides)
    bf = SSHBruteForce(s)
    det = SuccessAfterBruteForce(s, bruteforce=bf)
    for i in range(6):
        ev = ssh_failed(t=i)
        bf.evaluate(ev)
        det.evaluate(ev)
    return det


def test_success_after_bf_true_positive():
    det = _tripped_detector()
    ev = ssh_success(t=30)
    alerts = det.evaluate(ev)
    assert len(alerts) == 1
    a = alerts[0]
    assert a.rule_id == "SENTINEL-006"
    assert a.severity == "Critical"
    assert a.mitre_technique == "T1078"
    assert a.detected_at_ns == ev.ingested_ns
    # Repeated logins in the cooldown don't storm.
    assert det.evaluate(ssh_success(t=31)) == []


def test_success_after_bf_benign_no_prior_bruteforce():
    det = SuccessAfterBruteForce(settings())
    # 5 failures (below threshold) then success: a user who mistyped their password.
    for i in range(5):
        assert det.evaluate(ssh_failed(t=i)) == []
    assert det.evaluate(ssh_success(t=10)) == []


def test_success_after_bf_benign_other_ip():
    det = _tripped_detector()
    assert det.evaluate(ssh_success(t=30, ip="192.0.2.200")) == []


def test_success_after_bf_boundary_window():
    det = _tripped_detector(success_after_bf_window_s=100)
    # Tripped at t=5. 5 + 100 is inside (inclusive), 5 + 101 is outside.
    assert det.evaluate(ssh_success(t=106, user="other")) == []
    assert len(det.evaluate(ssh_success(t=105))) == 1


def test_success_after_bf_standalone_feeds_its_own_bruteforce():
    det = SuccessAfterBruteForce(settings())
    for i in range(6):
        det.evaluate(ssh_failed(t=i))
    assert len(det.evaluate(ssh_success(t=10))) == 1
