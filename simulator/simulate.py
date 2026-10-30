"""Traffic generator: realistic, labelled SSH / Nginx / VPN / badge-reader log lines.

Library use (the benchmark imports these)::

    generate_benign(n, seed, start)
    generate_attack_campaign(kind, seed, start)
    generate_mixed(n, attack_ratio, seed, start)

Each returns ``LabeledLine`` records whose ``line`` is the raw log text exactly as
the engine's parsers expect. ``label`` is ground truth for the benchmark only.

Service use (``python -m simulator.simulate``): generates traffic with ``start=now``
and POSTs batches of raw lines (never labels) to the engine's ``/ingest``.
Env: ENGINE_URL, SIM_SEED, SIM_RATE (events/sec), SIM_ATTACK_RATIO, SIM_BATCH_SIZE,
SIM_SUMMARY_INTERVAL_S, SENTINEL_API_KEY, SENTINEL_SECURE_FACILITY.

Dependencies are the stdlib and ``requests`` only: this module must not import
``sentinel`` so the simulator image stays small. The traffic is shaped around the
engine's default thresholds (see ``sentinel/config.py``):

* benign traffic never has more than 3 SSH or 3 web/VPN login failures from one IP
  in 5 minutes (rules 001/002 fire above 5 in 60 s);
* benign VPN logins only happen while the user is badged out (rule 005a);
* every benign user badges in at the secure facility before doing anything else, and
  on-prem SSH only happens while badged in (rule 005b);
* benign URIs include hard negatives ("select", "union", "drop", "--") that stay
  below the SQLi score threshold.
"""

from __future__ import annotations

import ipaddress
import json
import os
import random
import signal
import sys
import threading
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterator, Optional, Sequence

import requests

BENIGN = "benign"
T_BRUTE_FORCE = "T1110"
T_EXPLOIT_PUBLIC_APP = "T1190"
T_VALID_ACCOUNTS = "T1078"

ATTACK_KINDS: tuple[str, ...] = (
    "ssh_bruteforce",
    "ssh_bruteforce_then_success",
    "sqli",
    "path_traversal",
    "credential_stuffing",
    "impossible_travel_vpn",
    "onprem_ssh_no_badge",
)

# RFC 5737 documentation ranges. Attackers use the first two, benign
# external clients (home IPs, website visitors) the third.
ATTACKER_NETS = (ipaddress.ip_network("203.0.113.0/24"),
                 ipaddress.ip_network("198.51.100.0/24"))
BENIGN_EXTERNAL_NET = ipaddress.ip_network("192.0.2.0/24")

FACILITY = os.getenv("SENTINEL_SECURE_FACILITY", "HQ") or "HQ"

# Benign failure guard: at most this many failures per IP per guard window.
MAX_BENIGN_FAILURES = 3
FAILURE_GUARD_S = 300.0
# Benign users badge out before this much time on site, well inside both the
# 8 h on-site window (005a) and the 12 h badge lookback (005b).
MAX_ONSITE_S = 4 * 3600.0
# Nobody badges out right after badging in (or back in right after leaving).
MIN_STAY_S = 120.0
DEFAULT_MEAN_GAP_S = 1.0

_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def _new_rng(seed: Any) -> random.Random:
    return random.Random(seed)  # nosec B311 - non-cryptographic simulation data


# ------------------------------------------------------------------ records

@dataclass(frozen=True)
class LabeledLine:
    line: str
    label: str
    campaign_id: Optional[str]
    actor_ip: str
    actor_user: str
    ts: datetime

    @property
    def campaign_kind(self) -> Optional[str]:
        """``ssh_bruteforce`` for ``ssh_bruteforce-1a2b...``; None for benign lines."""
        if self.campaign_id is None:
            return None
        return self.campaign_id.rsplit("-", 1)[0]


# --------------------------------------------------------------- formatting

def _utc(ts: datetime) -> datetime:
    if ts.tzinfo is None:
        return ts.replace(tzinfo=timezone.utc)
    return ts.astimezone(timezone.utc)


def _iso(ts: datetime) -> str:
    return ts.isoformat(timespec="microseconds")


def _iso_z(ts: datetime) -> str:
    # Full microseconds: the line must carry exactly LabeledLine.ts, or two events a
    # few microseconds apart could collapse onto the same instant in the engine.
    return ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _floor_s(ts: datetime) -> datetime:
    return ts.replace(microsecond=0)


def ssh_line(ts: datetime, host: str, pid: int, msg: str) -> str:
    return f"{_iso(ts)} {host} sshd[{pid}]: {msg}"


def nginx_line(ts: datetime, ip: str, method: str, uri: str, status: int, size: int,
               referer: str = "-", ua: str = "-") -> str:
    stamp = (f"{ts.day:02d}/{_MONTHS[ts.month - 1]}/{ts.year:04d}:"
             f"{ts.hour:02d}:{ts.minute:02d}:{ts.second:02d} +0000")
    return (f'{ip} - - [{stamp}] "{method} {uri} HTTP/1.1" {status} {size} '
            f'"{referer}" "{ua}"')


def vpn_line(ts: datetime, user: str, ip: str, success: bool, **extra: Any) -> str:
    doc = {"ts": _iso_z(ts), "user": user, "src_ip": ip, "event": "vpn_login",
           "success": success, **extra}
    return json.dumps(doc, separators=(",", ":"))


def pacs_line(ts: datetime, badge_id: str, user: str, door: str, direction: str,
              granted: bool, facility: str = FACILITY) -> str:
    return ",".join((_iso_z(ts), badge_id, user, door, facility, direction,
                     "true" if granted else "false"))


# ------------------------------------------------------------- vocabularies

SSH_HOSTS = ("bastion01", "app01", "app02", "db01", "build01")
BROWSER_UAS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/130.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/18.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
)
ATTACK_UAS = ("sqlmap/1.8.10#stable (https://sqlmap.org)", "python-requests/2.32.3",
              "Mozilla/5.0 (compatible; Nmap Scripting Engine)", "curl/8.10.1",
              "Go-http-client/1.1")
REFERERS = ("-", "https://www.example.com/", "https://www.example.com/blog",
            "https://search.example.org/")

PAGES = ("/", "/about", "/pricing", "/contact", "/careers", "/blog",
         "/blog/2026/10/product-update", "/blog/2026/09/release-notes-4-2",
         "/docs/getting-started", "/docs/api/authentication", "/products",
         "/products/widget-pro", "/products?category=tools&page=2", "/cart",
         "/checkout", "/account/orders", "/robots.txt", "/sitemap.xml",
         "/.well-known/security.txt")
ASSETS = ("/static/css/main.3f9a1c.css", "/static/js/app.8c1d7e.js",
          "/static/js/vendor.41b0aa.js", "/static/img/logo.svg",
          "/static/img/hero@2x.webp", "/static/fonts/inter-var.woff2")
API_GETS = ("/api/v1/products?page=1", "/api/v1/products?page=2&sort=price",
            "/api/v1/cart", "/api/v1/users/me", "/api/v1/orders/48213",
            "/api/v1/search?q=usb-c+hub", "/api/v1/health")
API_POSTS = ("/api/v1/cart", "/api/v1/events", "/api/v1/newsletter")
NOT_FOUND = ("/favicon.ico", "/apple-touch-icon.png", "/apple-touch-icon-precomposed.png",
             "/old-promo", "/blog/2019/legacy-post", "/static/img/missing.png")
# Ordinary URIs that contain SQL-ish words or "--". Each scores below the SQLi
# threshold (at most one weak signal) and contains no traversal.
HARD_NEGATIVES = (
    "/blog/how-to-select-a-union-rep",
    "/search?q=select+a+plan",
    "/search?q=union+jobs+near+me",
    "/blog/drop-shipping-101",
    "/search?q=how+to+drop+a+class",
    "/careers/union-and-labor-relations",
    "/events/drop-in-sessions",
    "/docs/c--/getting-started",
    "/search?q=rock+--+roll",
    "/search?q=select+from+the+menu",
    "/products/select-from-our-range",
    "/search?q=mysql+select+tutorial",
    "/search?q=sleep+tracker",
    "/blog/or-1-more-thing",
    "/search?q=tom+and+jerry",
    "/wiki/Union_Station--History",
)

EMPLOYEES = ("a.khan", "b.osei", "c.novak", "d.ramirez", "e.lindqvist", "f.haddad",
             "g.tanaka", "h.mwangi", "i.petrov", "j.moreau", "k.singh", "l.oconnor",
             "m.rossi", "n.adeyemi", "o.berg", "p.silva")
# Victims of identity campaigns are kept apart from the benign population so the
# benign generator's badge state never disagrees with what a campaign did.
VICTIMS = ("q.nakamura", "r.fischer", "s.dubois", "t.kowalski", "u.okafor",
           "v.ivanova", "w.chen", "x.garcia", "y.larsen", "z.mensah")
HQ_DOORS = ("HQ-LOBBY", "HQ-GARAGE", "HQ-L2-EAST", "HQ-L3-LAB")

BRUTE_VALID_USERS = ("root", "admin", "ubuntu", "ec2-user", "git")
BRUTE_INVALID_USERS = ("oracle", "test", "postgres", "support", "guest", "ftpuser",
                       "pi", "user1", "hadoop", "deployer")
STUFFING_EXTRA_USERS = ("admin", "administrator", "vpnuser", "test", "helpdesk")

SQLI_URIS = (
    "/products?id=1%20UNION%20SELECT%20username,password%20FROM%20users--%20",
    "/products?id=-1%20UNION%20ALL%20SELECT%20table_name,2%20FROM"
    "%20information_schema.tables--%20",
    "/item?id=1%27%20OR%20%271%27=%271",
    "/login?user=admin%27%20OR%201=1--%20",
    "/search?q=1%27%20AND%20SLEEP(5)--%20",
    "/api/v1/items?id=1%27)%20AND%20BENCHMARK(5000000,MD5(1))%23",
    "/api/v1/search?q=x%27;SELECT%20pg_sleep(10)--%20",
    "/products?id=1;DROP%20TABLE%20users--%20",
    # Double-encoded variants.
    "/products?id=1%2520UNION%2520SELECT%2520NULL,NULL--%2520",
    "/item?id=%2527%2520OR%2520%25271%2527%253D%25271",
    "/search?q=1%2527%2520AND%2520SLEEP(5)--%2520",
)
TRAVERSAL_URIS = (
    "/static/../../../../etc/passwd",
    "/download?file=../../../../etc/passwd",
    "/download?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "/download?file=%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    "/static/%2e%2e/%2e%2e/%2e%2e/etc/shadow",
    "/images/..%5c..%5c..%5cwindows%5cwin.ini",
    "/cgi-bin/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
    "/index.php?page=../../../proc/self/environ",
)


# ------------------------------------------------------------ allocation

def _hosts(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> list[str]:
    return [str(h) for h in net.hosts()]


class _Allocator:
    """Hands out attacker IPs, victim users and internal IPs for campaigns.

    Shared across the campaigns of one workload so that concurrent campaigns never
    share an actor (an IP still in a rule's cooldown would hide the second one).
    """

    def __init__(self, rng: random.Random) -> None:
        self._rng = rng
        self._attacker_ips: deque[str] = deque()
        self._victim_uses: Counter[str] = Counter()
        self._internal_seq = 0

    def attacker_ip(self) -> str:
        if not self._attacker_ips:
            pool = [ip for net in ATTACKER_NETS for ip in _hosts(net)]
            self._rng.shuffle(pool)
            self._attacker_ips.extend(pool)
        return self._attacker_ips.popleft()

    def victim(self, kind: str) -> str:
        """A fresh account name per campaign: the pool first, then ``name2``, ``name3``..."""
        n = self._victim_uses[kind]
        self._victim_uses[kind] += 1
        # Disjoint halves per kind: an on-site victim must never be an on-prem one.
        half = len(VICTIMS) // 2
        pool = VICTIMS[:half] if kind == "impossible_travel_vpn" else VICTIMS[half:]
        rnd = n // len(pool)
        base = pool[n % len(pool)]
        return base if rnd == 0 else f"{base}{rnd + 1}"

    def internal_ip(self) -> str:
        # 172.20.0.0/16 is inside the engine's default internal CIDRs and disjoint
        # from the benign workstations (10.10.0.0/16).
        self._internal_seq += 1
        n = self._internal_seq % 65024
        return f"172.20.{n // 254}.{n % 254 + 1}"


# ------------------------------------------------------------ benign world

@dataclass
class _Employee:
    name: str
    badge_id: str
    workstation: str
    home_ip: str
    onsite: bool = False
    badged: bool = False
    last_in: Optional[datetime] = None
    last_out: Optional[datetime] = None


class BenignWorld:
    """Stateful benign traffic. Keeps employee badge state and per-IP failure history
    across calls, so a long-running service never contradicts itself."""

    def __init__(self, rng: random.Random, mean_gap_s: float = DEFAULT_MEAN_GAP_S) -> None:
        self.rng = rng
        self.mean_gap_s = mean_gap_s
        # Time of the last generated line; never moves backwards.
        self.clock = datetime.min.replace(tzinfo=timezone.utc)
        homes = rng.sample(range(1, 200), len(EMPLOYEES))
        self.employees = [
            _Employee(name=name, badge_id=f"B-{1000 + i}",
                      workstation=f"10.10.{1 + i // 50}.{10 + i % 50 * 4}",
                      home_ip=f"192.0.2.{homes[i]}")
            for i, name in enumerate(EMPLOYEES)
        ]
        self._visitors = [f"192.0.2.{n}" for n in range(1, 255)]
        self._failures: dict[tuple[str, str], deque[float]] = {}
        self._pending: deque[LabeledLine] = deque()
        self._pid = rng.randint(2000, 9000)

    # ---------------------------------------------------------- helpers

    def _tick(self, lo: float = 0.0) -> datetime:
        # At least 1 ms per line keeps every timestamp strictly increasing.
        gap = max(0.001, lo + self.rng.expovariate(1.0 / self.mean_gap_s))
        self.clock += timedelta(seconds=gap)
        return self.clock

    def _fail_allowed(self, bucket: str, ip: str, ts: datetime) -> bool:
        """At most MAX_BENIGN_FAILURES per IP per FAILURE_GUARD_S, per rule family."""
        dq = self._failures.setdefault((bucket, ip), deque())
        now = ts.timestamp()
        while dq and dq[0] < now - FAILURE_GUARD_S:
            dq.popleft()
        if len(dq) >= MAX_BENIGN_FAILURES:
            return False
        dq.append(now)
        return True

    def _next_pid(self) -> int:
        self._pid = 2000 + (self._pid + self.rng.randint(1, 40) - 2000) % 60000
        return self._pid

    @staticmethod
    def _line(line: str, ts: datetime, ip: str = "", user: str = "") -> LabeledLine:
        return LabeledLine(line=line, label=BENIGN, campaign_id=None, actor_ip=ip,
                           actor_user=user, ts=ts)

    # ---------------------------------------------------------- run

    def run(self, n: int, start: datetime) -> list[LabeledLine]:
        start = _utc(start)
        self.clock = max(self.clock, start)
        out: list[LabeledLine] = []
        while len(out) < n:
            if not self._pending:
                self._pending.extend(self._step())
            out.append(self._pending.popleft())
        return out

    def _step(self) -> list[LabeledLine]:
        roll = self.rng.random()
        if roll < 0.70:
            return self._nginx()
        if roll < 0.82:
            return self._badge()
        if roll < 0.92:
            return self._onprem_ssh() or self._badge()
        return self._vpn() or self._nginx()

    # ---------------------------------------------------------- nginx

    def _nginx(self) -> list[LabeledLine]:
        ts = _floor_s(self._tick())
        rng = self.rng
        roll = rng.random()
        if roll < 0.2:
            emp = rng.choice(self.employees)
            ip = emp.workstation if emp.onsite else emp.home_ip
        else:
            ip = rng.choice(self._visitors)
        ua = rng.choice(BROWSER_UAS)
        ref = rng.choice(REFERERS)
        roll = rng.random()
        method, status = "GET", 200
        if roll < 0.35:
            uri, size = rng.choice(PAGES), rng.randint(3_000, 60_000)
        elif roll < 0.60:
            uri, size = rng.choice(ASSETS), rng.randint(800, 400_000)
            status = rng.choice((200, 200, 200, 304))
        elif roll < 0.75:
            uri, size = rng.choice(API_GETS), rng.randint(80, 9_000)
        elif roll < 0.82:
            method, uri, size, status = "POST", rng.choice(API_POSTS), rng.randint(20, 400), 201
        elif roll < 0.88:
            uri, size, status = rng.choice(NOT_FOUND), 153, 404
        elif roll < 0.96:
            uri, size = rng.choice(HARD_NEGATIVES), rng.randint(3_000, 40_000)
        else:
            method, uri = "POST", rng.choice(("/login", "/login", "/wp-login.php"))
            if rng.random() < 0.25 and self._fail_allowed("login", ip, ts):
                status, size = 401, 512          # typo'd password
            else:
                status, size = 302, 0
        if status == 304:
            size = 0
        return [self._line(nginx_line(ts, ip, method, uri, status, size, ref, ua), ts, ip)]

    # ---------------------------------------------------------- badges

    def _badge(self) -> list[LabeledLine]:
        emp = self.rng.choice(self.employees)
        last = emp.last_in if emp.onsite else emp.last_out
        if last is not None and (self.clock - last).total_seconds() < MIN_STAY_S:
            return self._nginx()
        return self._badge_out(emp) if emp.onsite else self._badge_in(emp)

    def _badge_in(self, emp: _Employee) -> list[LabeledLine]:
        lines = []
        door = self.rng.choice(HQ_DOORS)
        if emp.badged and self.rng.random() < 0.05:   # mis-read card, then a re-swipe
            ts = self._tick()
            lines.append(self._line(pacs_line(ts, emp.badge_id, emp.name, door, "in", False),
                                    ts, user=emp.name))
        ts = self._tick()
        lines.append(self._line(pacs_line(ts, emp.badge_id, emp.name, door, "in", True),
                                ts, user=emp.name))
        emp.onsite, emp.badged, emp.last_in = True, True, ts
        return lines

    def _badge_out(self, emp: _Employee) -> list[LabeledLine]:
        ts = self._tick()
        line = pacs_line(ts, emp.badge_id, emp.name, self.rng.choice(HQ_DOORS[:2]), "out", True)
        emp.onsite, emp.last_out = False, ts
        return [self._line(line, ts, user=emp.name)]

    # ---------------------------------------------------------- ssh

    def _onprem_ssh(self) -> Optional[list[LabeledLine]]:
        now = self.clock
        stale = [e for e in self.employees
                 if e.onsite and e.last_in is not None
                 and (now - e.last_in).total_seconds() > MAX_ONSITE_S]
        if stale:
            return self._badge_out(stale[0])
        onsite = [e for e in self.employees if e.onsite]
        if not onsite:
            return None
        emp = self.rng.choice(onsite)
        host = self.rng.choice(SSH_HOSTS)
        ip = emp.workstation
        lines = []
        roll = self.rng.random()
        typos = 1 if roll < 0.12 else self.rng.randint(2, 3) if roll < 0.16 else 0
        for _ in range(typos):
            ts = self._tick()
            if not self._fail_allowed("ssh", ip, ts):
                break
            msg = (f"Failed password for {emp.name} from {ip} "
                   f"port {self.rng.randint(49152, 65535)} ssh2")
            lines.append(self._line(ssh_line(ts, host, self._next_pid(), msg), ts, ip, emp.name))
        ts = self._tick()
        method = "publickey" if self.rng.random() < 0.6 else "password"
        msg = f"Accepted {method} for {emp.name} from {ip} port {self.rng.randint(49152, 65535)}"
        msg += " ssh2: ED25519 SHA256:q7Hc0dE3xYbqk9Lm" if method == "publickey" else " ssh2"
        lines.append(self._line(ssh_line(ts, host, self._next_pid(), msg), ts, ip, emp.name))
        return lines

    # ---------------------------------------------------------- vpn

    def _vpn(self) -> Optional[list[LabeledLine]]:
        # Only users who have badged in before and are badged out right now.
        offsite = [e for e in self.employees if e.badged and not e.onsite]
        if not offsite:
            return None
        emp = self.rng.choice(offsite)
        ip = emp.home_ip
        lines = []
        extra = {"gateway": "vpn-gw01", "client": "openconnect"}
        if self.rng.random() < 0.08:
            ts = self._tick()
            if self._fail_allowed("login", ip, ts):
                lines.append(self._line(vpn_line(ts, emp.name, ip, False, **extra),
                                        ts, ip, emp.name))
        ts = self._tick()
        lines.append(self._line(vpn_line(ts, emp.name, ip, True, **extra), ts, ip, emp.name))
        return lines


# -------------------------------------------------------------- campaigns

class _Campaign:
    def __init__(self, kind: str, rng: random.Random, alloc: _Allocator) -> None:
        self.kind = kind
        self.rng = rng
        self.alloc = alloc
        self.id = f"{kind}-{rng.getrandbits(40):010x}"
        self.lines: list[LabeledLine] = []

    def add(self, line: str, ts: datetime, label: str, ip: str, user: str) -> None:
        self.lines.append(LabeledLine(line=line, label=label, campaign_id=self.id,
                                      actor_ip=ip, actor_user=user, ts=ts))

    def times(self, count: int, start: datetime, max_span_s: float) -> list[datetime]:
        """``count`` sorted times in ``[start, start + span)``, first one at ``start``."""
        span = self.rng.uniform(max_span_s * 0.3, max_span_s)
        offsets = sorted([0.0] + [self.rng.uniform(0, span) for _ in range(count - 1)])
        return [start + timedelta(seconds=o) for o in offsets]


def _ssh_bruteforce(c: _Campaign, start: datetime, then_success: bool) -> None:
    rng = c.rng
    ip = c.alloc.attacker_ip()
    host = rng.choice(SSH_HOSTS)
    pairs = rng.random() < 0.5    # sshd logs "Invalid user" + "Failed ... invalid user"
    pid = rng.randint(10_000, 30_000)
    # 8-40 attempts, all lines inside 28.5 s (the rule's window is 60 s).
    times = c.times(rng.randint(8, 40), start, 28.0)
    for i, ts in enumerate(times):
        port = rng.randint(32768, 60999)
        if pairs and rng.random() < 0.6:
            user = rng.choice(BRUTE_INVALID_USERS)
            c.add(ssh_line(ts, host, pid + i, f"Invalid user {user} from {ip} port {port}"),
                  ts, T_BRUTE_FORCE, ip, user)
            ts2 = ts + timedelta(seconds=rng.uniform(0.05, 0.4))
            msg = f"Failed password for invalid user {user} from {ip} port {port} ssh2"
            c.add(ssh_line(ts2, host, pid + i, msg), ts2, T_BRUTE_FORCE, ip, user)
        else:
            user = rng.choice(BRUTE_VALID_USERS)
            msg = f"Failed password for {user} from {ip} port {port} ssh2"
            c.add(ssh_line(ts, host, pid + i, msg), ts, T_BRUTE_FORCE, ip, user)
    if then_success:
        user = rng.choice(BRUTE_VALID_USERS)
        ts = c.lines[-1].ts + timedelta(seconds=rng.uniform(2.0, 20.0))
        msg = f"Accepted password for {user} from {ip} port {rng.randint(32768, 60999)} ssh2"
        c.add(ssh_line(ts, host, pid + len(times), msg), ts, T_VALID_ACCOUNTS, ip, user)


def _web_exploit(c: _Campaign, start: datetime, uris: Sequence[str]) -> None:
    rng = c.rng
    ip = c.alloc.attacker_ip()
    ua = rng.choice(ATTACK_UAS)
    chosen = rng.sample(list(uris), rng.randint(3, min(8, len(uris))))
    for ts, uri in zip(c.times(len(chosen), start, 20.0), chosen):
        ts = _floor_s(ts)
        status = rng.choice((200, 400, 403, 404, 500))
        line = nginx_line(ts, ip, "GET", uri, status, rng.randint(0, 2_000), "-", ua)
        c.add(line, ts, T_EXPLOIT_PUBLIC_APP, ip, "")


def _credential_stuffing(c: _Campaign, start: datetime) -> None:
    rng = c.rng
    # Web phase: failed form logins from one IP, all inside 40 s (window is 60 s).
    web_ip = c.alloc.attacker_ip()
    ua = rng.choice(ATTACK_UAS)
    path = rng.choice(("/login", "/wp-login.php"))
    for ts in c.times(rng.randint(8, 25), start, 40.0):
        ts = _floor_s(ts)
        c.add(nginx_line(ts, web_ip, "POST", path, 401, 512, "-", ua), ts, T_BRUTE_FORCE,
              web_ip, "")
    # VPN phase: failed logins across several usernames from a second IP.
    vpn_ip = c.alloc.attacker_ip()
    users = rng.sample(list(EMPLOYEES) + list(STUFFING_EXTRA_USERS), rng.randint(4, 10))
    vpn_start = c.lines[-1].ts + timedelta(seconds=rng.uniform(5.0, 60.0))
    for i, ts in enumerate(c.times(rng.randint(8, 20), vpn_start, 40.0)):
        user = users[i % len(users)]
        c.add(vpn_line(ts, user, vpn_ip, False, gateway="vpn-gw01"), ts, T_BRUTE_FORCE,
              vpn_ip, user)


def _impossible_travel_vpn(c: _Campaign, start: datetime) -> None:
    rng = c.rng
    ip = c.alloc.attacker_ip()
    user = c.alloc.victim(c.kind)
    badge_id = f"B-{rng.randint(5000, 5999)}"
    c.add(pacs_line(start, badge_id, user, "HQ-LOBBY", "in", True), start, T_VALID_ACCOUNTS,
          ip, user)
    ts = start + timedelta(seconds=rng.uniform(30, 300))
    c.add(pacs_line(ts, badge_id, user, "HQ-L3-LAB", "in", True), ts, T_VALID_ACCOUNTS,
          ip, user)
    # The real user is on site; someone else logs in remotely with their credentials.
    ts += timedelta(seconds=rng.uniform(120, 1800))
    c.add(vpn_line(ts, user, ip, True, gateway="vpn-gw01", client="openconnect"), ts,
          T_VALID_ACCOUNTS, ip, user)


def _onprem_ssh_no_badge(c: _Campaign, start: datetime) -> None:
    rng = c.rng
    ip = c.alloc.internal_ip()
    user = c.alloc.victim(c.kind)
    badge_id = f"B-{rng.randint(6000, 6999)}"
    # The user is a known badge holder: they were in yesterday (> 12 h lookback ago).
    t_in = start - timedelta(hours=rng.uniform(24, 30))
    t_out = t_in + timedelta(hours=rng.uniform(7, 9))
    c.add(pacs_line(t_in, badge_id, user, "HQ-LOBBY", "in", True), t_in, T_VALID_ACCOUNTS,
          ip, user)
    c.add(pacs_line(t_out, badge_id, user, "HQ-LOBBY", "out", True), t_out, T_VALID_ACCOUNTS,
          ip, user)
    host = rng.choice(SSH_HOSTS)
    msg = f"Accepted password for {user} from {ip} port {rng.randint(49152, 65535)} ssh2"
    c.add(ssh_line(start, host, rng.randint(10_000, 30_000), msg), start, T_VALID_ACCOUNTS,
          ip, user)


_BUILDERS: dict[str, Callable[[_Campaign, datetime], None]] = {
    "ssh_bruteforce": lambda c, s: _ssh_bruteforce(c, s, then_success=False),
    "ssh_bruteforce_then_success": lambda c, s: _ssh_bruteforce(c, s, then_success=True),
    "sqli": lambda c, s: _web_exploit(c, s, SQLI_URIS),
    "path_traversal": lambda c, s: _web_exploit(c, s, TRAVERSAL_URIS),
    "credential_stuffing": _credential_stuffing,
    "impossible_travel_vpn": _impossible_travel_vpn,
    "onprem_ssh_no_badge": _onprem_ssh_no_badge,
}


def _build_campaign(kind: str, rng: random.Random, alloc: _Allocator,
                    start: datetime) -> list[LabeledLine]:
    if kind not in _BUILDERS:
        raise ValueError(f"unknown campaign kind {kind!r}; expected one of {ATTACK_KINDS}")
    c = _Campaign(kind, rng, alloc)
    _BUILDERS[kind](c, _utc(start))
    return sorted(c.lines, key=lambda ln: ln.ts)


# ------------------------------------------------------------ generators

class TrafficGenerator:
    """Mixed benign + attack traffic with state that persists between chunks.

    The attack ratio is tracked over everything generated so far, so small service
    chunks still converge to ``attack_ratio`` even though campaigns are bursty.
    Campaign kinds rotate through a shuffled cycle: every kind appears once per
    ``len(ATTACK_KINDS)`` campaigns.
    """

    def __init__(self, seed: Any, attack_ratio: float,
                 mean_gap_s: float = DEFAULT_MEAN_GAP_S) -> None:
        if not 0.0 <= attack_ratio <= 1.0:
            raise ValueError("attack_ratio must be between 0 and 1")
        self.rng = _new_rng(seed)
        self.attack_ratio = attack_ratio
        self.mean_gap_s = mean_gap_s
        self.world = BenignWorld(_new_rng(self.rng.getrandbits(64)), mean_gap_s)
        self.alloc = _Allocator(_new_rng(self.rng.getrandbits(64)))
        self._kinds: deque[str] = deque()
        self.total = 0
        self.attack_total = 0

    def _next_kind(self) -> str:
        if not self._kinds:
            kinds = list(ATTACK_KINDS)
            self.rng.shuffle(kinds)
            self._kinds.extend(kinds)
        return self._kinds.popleft()

    def chunk(self, n: int, start: datetime) -> list[LabeledLine]:
        """About ``n`` lines (exactly ``n`` unless campaigns alone exceed it), sorted by ts."""
        start = _utc(start)
        start = max(start, self.world.clock)
        span_s = max(1.0, n * (1.0 - self.attack_ratio) * self.mean_gap_s)
        target = self.attack_ratio * (self.total + n) - self.attack_total
        attack: list[LabeledLine] = []
        while self.attack_ratio > 0 and len(attack) < target:
            offset = timedelta(seconds=self.rng.uniform(0, span_s))
            attack.extend(_build_campaign(self._next_kind(),
                                          _new_rng(self.rng.getrandbits(64)),
                                          self.alloc, start + offset))
        benign = self.world.run(max(0, n - len(attack)), start)
        self.total += len(attack) + len(benign)
        self.attack_total += len(attack)
        return sorted(benign + attack, key=lambda ln: ln.ts)


def generate_benign(n: int, seed: Any, start: datetime) -> list[LabeledLine]:
    """``n`` benign lines starting at ``start``; must raise no alerts."""
    return BenignWorld(_new_rng(seed)).run(n, start)


def generate_attack_campaign(kind: str, seed: Any, start: datetime) -> list[LabeledLine]:
    """One campaign of ``kind`` (see ATTACK_KINDS), starting around ``start``."""
    rng = _new_rng(seed)
    return _build_campaign(kind, rng, _Allocator(_new_rng(rng.getrandbits(64))), start)


def generate_mixed(n: int, attack_ratio: float, seed: Any,
                   start: datetime) -> list[LabeledLine]:
    """About ``n`` lines, ``attack_ratio`` of them from campaigns, interleaved by ts."""
    return TrafficGenerator(seed, attack_ratio).chunk(n, start)


# ---------------------------------------------------------------- service

API_KEY_HEADER = "X-API-Key"


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name, "").strip()
    return float(raw) if raw else default


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    return int(raw) if raw else default


@dataclass
class ServiceConfig:
    engine_url: str = "http://engine:8000"
    seed: str = "1337"
    rate: float = 20.0
    attack_ratio: float = 0.1
    batch_size: int = 50
    api_key: str = field(default="", repr=False)
    summary_interval_s: float = 30.0
    timeout_s: float = 10.0

    @classmethod
    def from_env(cls) -> "ServiceConfig":
        cfg = cls(
            engine_url=os.getenv("ENGINE_URL", cls.engine_url).rstrip("/"),
            seed=os.getenv("SIM_SEED", "").strip() or cls.seed,
            rate=_env_float("SIM_RATE", cls.rate),
            attack_ratio=_env_float("SIM_ATTACK_RATIO", cls.attack_ratio),
            batch_size=_env_int("SIM_BATCH_SIZE", cls.batch_size),
            api_key=os.getenv("SENTINEL_API_KEY", ""),
            summary_interval_s=_env_float("SIM_SUMMARY_INTERVAL_S", cls.summary_interval_s),
        )
        if cfg.rate <= 0:
            raise ValueError("SIM_RATE must be > 0")
        if cfg.batch_size < 1:
            raise ValueError("SIM_BATCH_SIZE must be >= 1")
        if not 0.0 <= cfg.attack_ratio <= 1.0:
            raise ValueError("SIM_ATTACK_RATIO must be between 0 and 1")
        return cfg


class _Retryable(Exception):
    pass


class Service:
    """Posts generated traffic to the engine until ``stop`` is set."""

    def __init__(self, cfg: ServiceConfig, stop: Optional[threading.Event] = None,
                 out: Callable[[str], None] = print) -> None:
        self.cfg = cfg
        self.stop = stop or threading.Event()
        self.out = out
        self.generator = TrafficGenerator(cfg.seed, cfg.attack_ratio, 1.0 / cfg.rate)
        self.by_label: Counter[str] = Counter()
        self.by_kind: Counter[str] = Counter()
        self.posted = 0
        self.batches = 0
        self.http_failures = 0
        self.dropped = 0
        self.alerts = 0

    def _headers(self) -> dict[str, str]:
        return {API_KEY_HEADER: self.cfg.api_key} if self.cfg.api_key else {}

    def _log(self, msg: str) -> None:
        self.out(f"[simulator] {msg}")

    def wait_for_engine(self) -> bool:
        """Block until GET /health reports ok. False if stopped first."""
        delay = 0.5
        while not self.stop.is_set():
            try:
                resp = requests.get(f"{self.cfg.engine_url}/health", timeout=self.cfg.timeout_s)
                if resp.status_code == 200 and resp.json().get("status") == "ok":
                    return True
            except (requests.RequestException, ValueError):
                pass
            self.stop.wait(delay)
            delay = min(delay * 2, 10.0)
        return False

    def post(self, lines: Sequence[LabeledLine]) -> bool:
        """POST one batch of raw lines. Raises _Retryable on connection errors and
        5xx; returns False (batch dropped) on other HTTP errors."""
        # Ground-truth labels stay here: only the raw text goes to the engine.
        body = {"lines": [ln.line for ln in lines]}
        try:
            resp = requests.post(f"{self.cfg.engine_url}/ingest", json=body,
                                 headers=self._headers(), timeout=self.cfg.timeout_s)
        except requests.RequestException as exc:
            self.http_failures += 1
            raise _Retryable(type(exc).__name__) from None
        if resp.status_code >= 500:
            self.http_failures += 1
            raise _Retryable(f"HTTP {resp.status_code}")
        if resp.status_code != 200:
            self.http_failures += 1
            self.dropped += len(lines)
            self._log(f"engine rejected batch: HTTP {resp.status_code}; dropped {len(lines)}")
            return False
        try:
            self.alerts += int(resp.json().get("alerts", 0))
        except (ValueError, TypeError, AttributeError):
            pass
        return True

    def _send(self, batch: Sequence[LabeledLine]) -> None:
        """Deliver a batch, riding out engine restarts. Returns when sent or stopped."""
        while not self.stop.is_set():
            try:
                if self.post(batch):
                    self.posted += len(batch)
                    self.batches += 1
                    for ln in batch:
                        self.by_label[ln.label] += 1
                        self.by_kind[ln.campaign_kind or BENIGN] += 1
                return
            except _Retryable as exc:
                self._log(f"engine unavailable ({exc}); waiting for /health")
                if not self.wait_for_engine():
                    return

    def summary(self) -> str:
        labels = ", ".join(f"{k}={v}" for k, v in sorted(self.by_label.items()))
        kinds = ", ".join(f"{k}={v}" for k, v in sorted(self.by_kind.items()))
        return (f"posted={self.posted} batches={self.batches} alerts={self.alerts} "
                f"http_failures={self.http_failures} dropped={self.dropped} | "
                f"labels: {labels or '-'} | kinds: {kinds or '-'}")

    def batches_forever(self) -> Iterator[list[LabeledLine]]:
        # About 10 s of traffic per chunk, capped so a high SIM_RATE never stalls.
        chunk_n = max(self.cfg.batch_size * 5, min(int(self.cfg.rate * 10), 2000))
        while True:
            lines = self.generator.chunk(chunk_n, datetime.now(timezone.utc))
            for i in range(0, len(lines), self.cfg.batch_size):
                yield lines[i:i + self.cfg.batch_size]

    def run(self) -> int:
        self._log(f"waiting for engine at {self.cfg.engine_url}")
        if not self.wait_for_engine():
            return 0
        self._log(f"engine up; rate={self.cfg.rate}/s attack_ratio={self.cfg.attack_ratio} "
                  f"batch={self.cfg.batch_size} seed={self.cfg.seed}")
        next_send = time.monotonic()
        next_summary = next_send + self.cfg.summary_interval_s
        for batch in self.batches_forever():
            if self.stop.wait(max(0.0, next_send - time.monotonic())):
                break
            self._send(batch)
            if self.stop.is_set():
                break
            now = time.monotonic()
            # Pace by SIM_RATE; after a long outage, resume at rate instead of bursting.
            next_send = max(next_send + len(batch) / self.cfg.rate, now - 1.0)
            if now >= next_summary:
                self._log(self.summary())
                next_summary = now + self.cfg.summary_interval_s
        self._log("stopping; " + self.summary())
        return 0


def main() -> int:
    try:
        cfg = ServiceConfig.from_env()
    except ValueError as exc:
        print(f"[simulator] bad configuration: {exc}", file=sys.stderr)
        return 2
    stop = threading.Event()

    def _handle(signum: int, _frame: Any) -> None:
        stop.set()

    signal.signal(signal.SIGTERM, _handle)
    signal.signal(signal.SIGINT, _handle)
    service = Service(cfg, stop, out=lambda msg: print(msg, flush=True))
    return service.run()


if __name__ == "__main__":
    sys.exit(main())
