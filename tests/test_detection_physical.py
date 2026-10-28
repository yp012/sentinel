from sentinel.detection import ImpossibleTravel
from tests.factories import badge, settings, ssh_success, vpn_login

HOUR = 3600


def make(**overrides):
    return ImpossibleTravel(settings(**overrides))


# ------------------------------------------------- (a) remote login while on-site

def test_vpn_from_outside_while_badged_in_fires():
    det = make()
    assert det.evaluate(badge(t=0, direction="in")) == []
    ev = vpn_login(t=2 * HOUR, ip="198.51.100.20")
    alerts = det.evaluate(ev)
    assert len(alerts) == 1
    a = alerts[0]
    assert a.rule_id == "SENTINEL-005"
    assert a.severity == "Critical"
    assert a.mitre_technique == "T1078"
    assert a.user == "alice"
    assert a.src_ip == "198.51.100.20"
    assert a.evidence["scenario"] == "remote_login_while_onsite"
    assert a.detected_at_ns == ev.ingested_ns


def test_vpn_after_badge_out_is_benign():
    det = make()
    det.evaluate(badge(t=0, direction="in"))
    det.evaluate(badge(t=HOUR, direction="out"))
    assert det.evaluate(vpn_login(t=2 * HOUR)) == []


def test_vpn_from_internal_ip_while_onsite_is_benign():
    det = make()
    det.evaluate(badge(t=0, direction="in"))
    assert det.evaluate(vpn_login(t=60, ip="10.20.30.40")) == []


def test_vpn_failed_login_while_onsite_is_benign():
    det = make()
    det.evaluate(badge(t=0, direction="in"))
    assert det.evaluate(vpn_login(t=60, success=False)) == []


def test_badge_denied_or_other_facility_does_not_count_as_onsite():
    det = make()
    det.evaluate(badge(t=0, direction="in", granted=False))
    det.evaluate(badge(t=0, user="bob", direction="in", facility="Branch-Paris"))
    assert det.evaluate(vpn_login(t=60)) == []
    assert det.evaluate(vpn_login(t=60, user="bob")) == []


def test_onsite_window_boundary():
    det = make(onsite_window_s=HOUR)
    det.evaluate(badge(t=0, direction="in"))
    det.evaluate(badge(t=0, user="bob", direction="in"))
    assert len(det.evaluate(vpn_login(t=HOUR))) == 1            # exactly at the edge
    assert det.evaluate(vpn_login(t=HOUR + 1, user="bob")) == []  # one second past


def test_out_of_order_late_badge_in_triggers_on_arrival():
    det = make()
    vpn = vpn_login(t=HOUR)
    assert det.evaluate(vpn) == []  # badge record not here yet
    late_badge = badge(t=0, direction="in")
    alerts = det.evaluate(late_badge)
    assert len(alerts) == 1
    assert alerts[0].src_ip == vpn.src_ip
    assert alerts[0].detected_at_ns == late_badge.ingested_ns
    # Re-delivering the same badge doesn't re-alert.
    assert det.evaluate(badge(t=0, direction="in")) == []


def test_out_of_order_badge_after_vpn_time_is_ignored():
    det = make()
    det.evaluate(vpn_login(t=0))
    assert det.evaluate(badge(t=HOUR, direction="in")) == []


def test_out_of_order_late_badge_out_is_respected_for_later_events():
    det = make()
    det.evaluate(badge(t=0, direction="in"))
    det.evaluate(badge(t=2 * HOUR, direction="in", user="bob"))
    det.evaluate(badge(t=HOUR, direction="out"))  # arrives after a newer event for bob
    assert det.evaluate(vpn_login(t=90 * 60)) == []


# ------------------------------------------------ (b) on-prem access, no badge-in

def test_onprem_ssh_without_badge_in_fires():
    det = make()
    det.evaluate(badge(t=-2 * 24 * HOUR, direction="in"))  # known holder, badged days ago
    ev = ssh_success(t=0, ip="10.0.5.10", user="alice")
    alerts = det.evaluate(ev)
    assert len(alerts) == 1
    assert alerts[0].evidence["scenario"] == "onprem_access_without_badge_in"
    assert alerts[0].detected_at_ns == ev.ingested_ns
    assert det.evaluate(ssh_success(t=10, ip="10.0.5.10", user="alice")) == []  # cooldown


def test_onprem_ssh_after_badge_in_is_benign():
    det = make()
    det.evaluate(badge(t=0, direction="in"))
    assert det.evaluate(ssh_success(t=HOUR, ip="10.0.5.10", user="alice")) == []


def test_external_ssh_and_unknown_users_are_ignored_by_rule_b():
    det = make()
    det.evaluate(badge(t=-2 * 24 * HOUR, direction="in"))
    assert det.evaluate(ssh_success(t=0, ip="198.51.100.5", user="alice")) == []
    assert det.evaluate(ssh_success(t=0, ip="10.0.5.10", user="svc-backup")) == []


def test_unknown_users_checked_when_known_badge_not_required():
    det = make(require_known_badge=False)
    assert len(det.evaluate(ssh_success(t=0, ip="10.0.5.10", user="svc-backup"))) == 1


def test_badge_lookback_boundary():
    det = make(badge_lookback_s=HOUR)
    det.evaluate(badge(t=0, direction="in"))
    det.evaluate(badge(t=0, user="bob", direction="in"))
    assert det.evaluate(ssh_success(t=HOUR, ip="10.0.0.1", user="alice")) == []
    assert len(det.evaluate(ssh_success(t=HOUR + 1, ip="10.0.0.1", user="bob"))) == 1


def test_internal_cidrs_come_from_config():
    det = make(internal_cidrs=("100.64.0.0/10",))
    det.evaluate(badge(t=0, direction="in"))
    # 10.x is now "external" for VPN purposes.
    assert len(det.evaluate(vpn_login(t=60, ip="10.1.1.1"))) == 1
