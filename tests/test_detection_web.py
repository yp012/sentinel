import pytest

from sentinel.detection import PathTraversal, SQLInjection
from sentinel.detection.web_attack import sqli_score
from tests.factories import http_get, settings, ssh_failed

# ------------------------------------------------------------- SENTINEL-003

SQLI_ATTACKS = [
    "/products?id=1%20UNION%20SELECT%20username,password%20FROM%20users--%20",
    "/login?user=admin'%20OR%201=1--%20",
    "/login?user=admin'%20OR%20'1'='1",
    "/item?id=1'%20AND%20SLEEP(5)--%20-",
    "/item?id=1%20AND%20BENCHMARK(5000000,MD5(1))%23",
    "/q?x=1%20union%20select%20table_name%20from%20information_schema.tables",
    "/q?id=1;DROP%20TABLE%20users",
    "/q?id=1%20UNION/**/SELECT/**/0x61646d696e",
    # Double-encoded: %2527 -> %27 -> '
    "/q?id=1%2527%2520OR%25201%253D1--%2520",
]


@pytest.mark.parametrize("uri", SQLI_ATTACKS)
def test_sqli_true_positives(uri):
    ev = http_get(uri)
    alerts = SQLInjection(settings()).evaluate(ev)
    assert len(alerts) == 1, sqli_score(ev.fields["uri"])
    a = alerts[0]
    assert a.rule_id == "SENTINEL-003"
    assert a.mitre_technique == "T1190"
    assert a.detected_at_ns == ev.ingested_ns
    assert a.evidence["score"] >= 4


@pytest.mark.parametrize("uri", [
    "/search?q=how+to+select+a+union+rep",
    "/blog/select-from-the-menu",
    "/docs/sql/select-statement",
    "/shop?category=selected&sort=price&order=asc",
    "/search?q=rock+and+roll+--+best+of",
    "/api/v1/users/42",
    "/news?title=Let's+select+the+best+one",
])
def test_sqli_benign_does_not_fire(uri):
    assert SQLInjection(settings()).evaluate(http_get(uri)) == []


def test_sqli_boundary_score_threshold():
    # union_select alone scores exactly 5.
    ev = http_get("/q?x=union%20select")
    assert sqli_score(ev.fields["uri"])[0] == 5
    assert len(SQLInjection(settings(sqli_score_threshold=5)).evaluate(ev)) == 1
    assert SQLInjection(settings(sqli_score_threshold=6)).evaluate(ev) == []


def test_sqli_boundary_single_weak_signal_below_default():
    # time-based function alone (3) does not fire; adding a comment (3 + 2) does.
    det = SQLInjection(settings())
    assert det.evaluate(http_get("/api?fn=sleep(5)")) == []
    assert len(det.evaluate(http_get("/api?fn=sleep(5)--%20"))) == 1


def test_sqli_severity_scales_with_score():
    det = SQLInjection(settings())
    medium = det.evaluate(http_get("/q?x=union%20select"))[0]
    critical = det.evaluate(http_get(
        "/q?id=1'%20UNION%20SELECT%20table_name%20FROM%20information_schema.tables--%20"))[0]
    assert medium.severity == "Medium"
    assert critical.severity == "Critical"


def test_sqli_ignores_non_http_events():
    assert SQLInjection(settings()).evaluate(ssh_failed()) == []


# ------------------------------------------------------------- SENTINEL-004

@pytest.mark.parametrize("uri,sensitive", [
    ("/download?file=../../../../etc/passwd", True),
    ("/static/..%2f..%2f..%2fetc%2fshadow", True),
    ("/static/%2e%2e%2f%2e%2e%2fboot.ini", True),
    ("/static/%252e%252e%252f%252e%252e%252fwindows/win.ini", True),
    ("/files/..\\..\\windows\\win.ini", True),
    ("/img/..%5c..%5cconfig.php", False),
    ("/a/%c0%ae%c0%ae/secret", False),
    ("/view?page=/etc/passwd", True),
])
def test_traversal_true_positives(uri, sensitive):
    ev = http_get(uri)
    alerts = PathTraversal(settings()).evaluate(ev)
    assert len(alerts) == 1, ev.fields
    a = alerts[0]
    assert a.rule_id == "SENTINEL-004"
    assert a.mitre_technique == "T1190"
    assert a.detected_at_ns == ev.ingested_ns
    assert bool(a.evidence["sensitive_targets"]) is sensitive


@pytest.mark.parametrize("uri", [
    "/files/report..final.pdf",
    "/docs/v1...v2/compare",
    "/blog/etc-passwords-guide",
    "/static/app.js?v=1.2.3",
    "/a/./b/c.html",
])
def test_traversal_benign_does_not_fire(uri):
    assert PathTraversal(settings()).evaluate(http_get(uri)) == []


def test_traversal_boundary_single_segment_and_dot_runs():
    det = PathTraversal(settings())
    assert len(det.evaluate(http_get("/a/../b"))) == 1  # one traversal segment fires
    assert det.evaluate(http_get("/a/.../b")) == []     # three dots is a filename
    assert det.evaluate(http_get("/a/..b/c")) == []     # ".." not a whole segment


def test_traversal_severity():
    det = PathTraversal(settings())
    assert det.evaluate(http_get("/x?f=../../etc/passwd"))[0].severity == "Critical"
    assert det.evaluate(http_get("/x?f=../../app/config.yml"))[0].severity == "High"
    assert det.evaluate(http_get("/x?f=/etc/passwd"))[0].severity == "High"


def test_traversal_counts_every_sequence():
    alert = PathTraversal(settings()).evaluate(http_get("/x?f=../../../../etc/passwd"))[0]
    assert alert.evidence["traversal_sequences"] == 4
