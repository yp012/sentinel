import os
import threading
from datetime import datetime, timezone

import pytest

from sentinel.parsers import detect_format, nginx, pacs, parse_any, ssh, vpn
from sentinel.pipeline import tail_file

NOW = datetime(2026, 10, 27, 12, 0, 0, tzinfo=timezone.utc)


# --------------------------------------------------------------------------- ssh

def test_ssh_failed_password():
    line = ("Oct 27 10:15:32 web01 sshd[2211]: Failed password for root "
            "from 203.0.113.7 port 51022 ssh2\n")
    ev = ssh.parse_line(line, now=NOW)
    assert ev is not None
    assert ev.source == "ssh"
    assert ev.event_type == "ssh_failed"
    assert ev.user == "root"
    assert ev.src_ip == "203.0.113.7"
    assert ev.ts == datetime(2026, 10, 27, 10, 15, 32, tzinfo=timezone.utc)
    assert ev.fields["port"] == 51022
    assert ev.fields["auth_method"] == "password"
    assert ev.fields["invalid_user"] is False
    assert ev.raw == line.rstrip("\n")


def test_ssh_failed_password_invalid_user():
    line = ("Oct  7 03:01:02 web01 sshd[99]: Failed password for invalid user oracle "
            "from 198.51.100.4 port 40000 ssh2")
    ev = ssh.parse_line(line, now=NOW)
    assert ev is not None
    assert ev.event_type == "ssh_failed"
    assert ev.user == "oracle"
    assert ev.fields["invalid_user"] is True
    assert ev.ts.day == 7


def test_ssh_invalid_user_line():
    ev = ssh.parse_line(
        "Oct 27 10:15:30 web01 sshd[2211]: Invalid user admin from 203.0.113.7 port 51020",
        now=NOW)
    assert ev is not None
    assert ev.event_type == "ssh_failed"
    assert ev.user == "admin"
    assert ev.fields["reason"] == "invalid_user"
    assert ev.fields["invalid_user"] is True


@pytest.mark.parametrize("method", ["password", "publickey"])
def test_ssh_accepted(method):
    suffix = ": RSA SHA256:abcDEF123" if method == "publickey" else ""
    line = (f"Oct 27 11:00:00 web01 sshd[3000]: Accepted {method} for alice "
            f"from 10.0.0.5 port 60000 ssh2{suffix}")
    ev = ssh.parse_line(line, now=NOW)
    assert ev is not None
    assert ev.event_type == "ssh_success"
    assert ev.user == "alice"
    assert ev.src_ip == "10.0.0.5"
    assert ev.fields["auth_method"] == method


def test_ssh_iso_timestamp_and_sshd_session():
    line = ("2026-10-27T10:15:32.123456+02:00 web01 sshd-session[5]: Failed publickey for "
            "bob from 2001:db8::1 port 22 ssh2")
    ev = ssh.parse_line(line)
    assert ev is not None
    assert ev.src_ip == "2001:db8::1"
    assert ev.ts.utcoffset().total_seconds() == 0
    assert ev.ts.hour == 8


def test_ssh_year_rollover():
    jan = datetime(2027, 1, 1, 0, 5, tzinfo=timezone.utc)
    ev = ssh.parse_line(
        "Dec 31 23:59:59 web01 sshd[1]: Invalid user x from 192.0.2.1", now=jan)
    assert ev is not None
    assert ev.ts.year == 2026


def test_ssh_username_cannot_spoof_ip():
    # Attacker-chosen username containing a fake "from <ip> port" clause.
    line = ("Oct 27 10:00:00 web01 sshd[1]: Failed password for invalid user "
            "x from 6.6.6.6 port 22 ssh2 from 203.0.113.9 port 4444 ssh2")
    ev = ssh.parse_line(line, now=NOW)
    assert ev is not None
    assert ev.src_ip == "203.0.113.9"


def test_ssh_empty_invalid_username():
    ev = ssh.parse_line(
        "Oct 27 10:00:00 web01 sshd[1]: Failed password for invalid user  "
        "from 192.0.2.8 port 22 ssh2", now=NOW)
    assert ev is not None
    assert ev.user == ""
    assert ev.fields["invalid_user"] is True


@pytest.mark.parametrize("line", [
    "",
    "garbage",
    "Oct 27 10:00:00 web01 sshd[1]: Connection closed by 1.2.3.4 port 22 [preauth]",
    "Oct 27 10:00:00 web01 cron[1]: Failed password for root from 1.2.3.4 port 22 ssh2",
    "Oct 27 10:00:00 web01 sshd[1]: Failed password for root from not-an-ip port 22 ssh2",
    "Foo 27 10:00:00 web01 sshd[1]: Invalid user a from 1.2.3.4",
    "Feb 30 10:00:00 web01 sshd[1]: Invalid user a from 1.2.3.4",
])
def test_ssh_malformed_returns_none(line):
    assert ssh.parse_line(line, now=NOW) is None


# ------------------------------------------------------------------------- nginx

NGINX_OK = ('203.0.113.7 - - [27/Oct/2026:10:15:32 +0200] "GET /index.html?q=1 HTTP/1.1" '
            '200 512 "https://example.com/" "Mozilla/5.0 (X11; Linux x86_64)"')


def test_nginx_valid():
    ev = nginx.parse_line(NGINX_OK)
    assert ev is not None
    assert ev.source == "nginx"
    assert ev.event_type == "http_request"
    assert ev.src_ip == "203.0.113.7"
    assert ev.user == ""
    assert ev.ts == datetime(2026, 10, 27, 8, 15, 32, tzinfo=timezone.utc)
    f = ev.fields
    assert f["method"] == "GET"
    assert f["uri"] == "/index.html?q=1"
    assert f["path"] == "/index.html"
    assert f["status"] == 200
    assert f["bytes"] == 512
    assert f["referer"] == "https://example.com/"
    assert f["user_agent"] == "Mozilla/5.0 (X11; Linux x86_64)"
    assert f["protocol"] == "HTTP/1.1"


def test_nginx_double_encoded_uri():
    # %253Cscript%253E -> %3Cscript%3E -> <script>
    line = ('198.51.100.9 - - [27/Oct/2026:10:00:00 +0000] '
            '"GET /search?q=%253Cscript%253Ealert(1)%253C%252Fscript%253E HTTP/1.1" '
            '200 10 "-" "curl/8.0"')
    ev = nginx.parse_line(line)
    assert ev is not None
    assert ev.fields["uri"] == "/search?q=<script>alert(1)</script>"
    assert ev.fields["uri_raw"].startswith("/search?q=%253C")
    assert ev.fields["decode_rounds"] == 2


def test_nginx_triple_encoding_stops_after_two_rounds():
    decoded, rounds = nginx.decode_uri("%25253C")
    assert decoded == "%3C"
    assert rounds == 2


@pytest.mark.parametrize("path,status,expected", [
    ("/login", 401, "http_login_failed"),
    ("/wp-login.php", 403, "http_login_failed"),
    ("/login/", 401, "http_login_failed"),
    ("/login", 200, "http_request"),
    ("/other", 401, "http_request"),
])
def test_nginx_login_failed(path, status, expected):
    line = (f'192.0.2.50 - - [27/Oct/2026:10:00:00 +0000] "POST {path} HTTP/1.1" '
            f'{status} 0 "-" "python-requests/2.31"')
    ev = nginx.parse_line(line)
    assert ev is not None
    assert ev.event_type == expected


def test_nginx_get_login_401_is_not_failed_login():
    line = ('192.0.2.50 - - [27/Oct/2026:10:00:00 +0000] "GET /login HTTP/1.1" '
            '401 0 "-" "x"')
    assert nginx.parse_line(line).event_type == "http_request"


def test_nginx_garbage_request_and_dash_bytes():
    line = ('192.0.2.1 - bob [27/Oct/2026:10:00:00 +0000] "\\x16\\x03\\x01\\x02" 400 - "-" "-"')
    ev = nginx.parse_line(line)
    assert ev is not None
    assert ev.user == "bob"
    assert ev.fields["method"] == ""
    assert ev.fields["bytes"] == 0
    assert ev.fields["status"] == 400


@pytest.mark.parametrize("line", [
    "",
    "not a log line",
    'bad-ip - - [27/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "-"',
    '1.2.3.4 - - [99/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "-"',
    '1.2.3.4 - - [27/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" abc 1 "-" "-"',
])
def test_nginx_malformed_returns_none(line):
    assert nginx.parse_line(line) is None


# --------------------------------------------------------------------------- vpn

def test_vpn_valid():
    line = ('{"ts":"2026-10-27T10:00:00Z","user":"alice","src_ip":"198.51.100.20",'
            '"event":"vpn_login","success":true,"country":"DE"}')
    ev = vpn.parse_line(line)
    assert ev is not None
    assert ev.source == "vpn"
    assert ev.event_type == "vpn_login"
    assert ev.user == "alice"
    assert ev.src_ip == "198.51.100.20"
    assert ev.ts == datetime(2026, 10, 27, 10, 0, tzinfo=timezone.utc)
    assert ev.fields == {"success": True, "country": "DE"}


def test_vpn_failed_login_epoch_ts():
    line = ('{"ts": 1793095200, "user": "bob", "src_ip": "192.0.2.3", '
            '"event": "vpn_login", "success": false}')
    ev = vpn.parse_line(line)
    assert ev is not None
    assert ev.fields["success"] is False
    assert ev.ts.tzinfo is not None


@pytest.mark.parametrize("line", [
    "",
    "{not json",
    "[1, 2, 3]",
    '{"ts":"2026-10-27T10:00:00Z","user":"a","src_ip":"1.2.3.4","event":"vpn_login"}',
    '{"ts":"2026-10-27T10:00:00Z","user":"a","src_ip":"1.2.3.4","event":"logout",'
    '"success":true}',
    '{"ts":"2026-10-27T10:00:00Z","user":"a","src_ip":"1.2.3.4","event":"vpn_login",'
    '"success":"yes"}',
    '{"ts":"yesterday","user":"a","src_ip":"1.2.3.4","event":"vpn_login","success":true}',
    '{"ts":"2026-10-27T10:00:00Z","user":"a","src_ip":"nope","event":"vpn_login",'
    '"success":true}',
    '{"ts":"2026-10-27T10:00:00Z","user":5,"src_ip":"1.2.3.4","event":"vpn_login",'
    '"success":true}',
])
def test_vpn_malformed_returns_none(line):
    assert vpn.parse_line(line) is None


# -------------------------------------------------------------------------- pacs

def test_pacs_valid():
    ev = pacs.parse_line("2026-10-27T08:59:00Z,B-1001,alice,D-12,HQ-London,in,true")
    assert ev is not None
    assert ev.source == "pacs"
    assert ev.event_type == "badge_swipe"
    assert ev.user == "alice"
    assert ev.src_ip == ""
    assert ev.fields == {
        "badge_id": "B-1001",
        "door": "D-12",
        "facility": "HQ-London",
        "direction": "in",
        "granted": True,
    }


def test_pacs_denied_quoted_and_case():
    ev = pacs.parse_line('2026-10-27T09:00:00+01:00,B-7,bob,"Lobby, North",HQ,OUT,denied')
    assert ev is not None
    assert ev.fields["door"] == "Lobby, North"
    assert ev.fields["direction"] == "out"
    assert ev.fields["granted"] is False
    assert ev.ts.hour == 8


@pytest.mark.parametrize("line", [
    "",
    "ts,badge_id,user,door,facility,direction,granted",
    "2026-10-27T08:59:00Z,B-1,alice,D-1,HQ,in",
    "2026-10-27T08:59:00Z,B-1,alice,D-1,HQ,sideways,true",
    "2026-10-27T08:59:00Z,B-1,alice,D-1,HQ,in,maybe",
    "2026-10-27T08:59:00Z,,alice,D-1,HQ,in,true",
])
def test_pacs_malformed_returns_none(line):
    assert pacs.parse_line(line) is None


# --------------------------------------------------------------------- dispatcher

@pytest.mark.parametrize("line,fmt,source", [
    ("Oct 27 10:15:32 web01 sshd[1]: Invalid user a from 192.0.2.1 port 1", "ssh", "ssh"),
    (NGINX_OK, "nginx", "nginx"),
    ('{"ts":"2026-10-27T10:00:00Z","user":"a","src_ip":"192.0.2.1",'
     '"event":"vpn_login","success":true}', "vpn", "vpn"),
    ("2026-10-27T08:59:00Z,B-1,alice,D-1,HQ,in,true", "pacs", "pacs"),
])
def test_parse_any_routes(line, fmt, source):
    assert detect_format(line) == fmt
    ev = parse_any(line)
    assert ev is not None
    assert ev.source == source


@pytest.mark.parametrize("line", ["", "   ", "hello world", "{broken", "\x00\xff"])
def test_parse_any_unknown_returns_none(line):
    assert parse_any(line) is None


def test_parsers_never_raise_on_odd_input():
    weird = ["\x00" * 50, "{" * 1000, "," * 6, '"' * 9, "\udcff", "Oct 99 99:99:99 h sshd: x"]
    for line in weird:
        for parse in (ssh.parse_line, nginx.parse_line, vpn.parse_line, pacs.parse_line,
                      parse_any):
            assert parse(line) is None


def test_label_untouched_by_parsers():
    ev = parse_any(NGINX_OK)
    assert ev.label is None


# --------------------------------------------------------------------- tail_file

def test_tail_file_reads_complete_lines_and_handles_truncation(tmp_path):
    path = tmp_path / "app.log"
    path.write_bytes(b"one\ntwo\r\npart")
    stop = threading.Event()
    gen = tail_file(str(path), from_start=True, poll_interval=0.01, stop_event=stop)

    assert next(gen) == "one"
    assert next(gen) == "two"

    with open(path, "ab") as fh:
        fh.write(b"ial\n")
    assert next(gen) == "partial"

    # copytruncate-style rotation: file shrinks, reading restarts from the top.
    with open(path, "wb") as fh:
        fh.write(b"new\n")
    assert next(gen) == "new"

    stop.set()
    assert list(gen) == []


def test_tail_file_skips_existing_content_by_default(tmp_path):
    path = tmp_path / "app.log"
    path.write_text("old\n")
    stop = threading.Event()
    gen = tail_file(str(path), poll_interval=0.01, stop_event=stop)
    stop.set()
    assert list(gen) == []
    assert os.path.exists(path)
