"""Simulated host firewall.

Rules live in memory and in a JSON file. Each change renders the matching
iptables command into a command log. Real ``iptables`` runs only when
``SENTINEL_REAL_FIREWALL=1``.

Safety guard: private, loopback, link-local, internal-CIDR and allowlisted
addresses are never blocked, so a spoofed or misattributed event cannot lock
operators out.
"""

from __future__ import annotations

import json
import logging
import os
# subprocess is only used for the opt-in real firewall, always with a list argv.
import subprocess  # nosec B404
import tempfile
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Callable, Optional

from sentinel import config
from sentinel.config import Settings
from sentinel.net import IPAddress, is_private_or_special, parse_ip, parse_networks

logger = logging.getLogger(__name__)


class FirewallError(RuntimeError):
    """The real firewall command failed."""


class BlockRefused(ValueError):
    """The safety guard refused to block this address."""


@dataclass(frozen=True)
class FirewallRule:
    ip: str
    reason: str
    created_at: float              # epoch seconds (wall clock: rules outlive the process)
    expires_at: Optional[float]    # None = permanent
    command: str

    def expired(self, now: float) -> bool:
        return self.expires_at is not None and now >= self.expires_at

    def to_dict(self) -> dict:
        d = asdict(self)
        d["created_at_iso"] = _iso(self.created_at)
        d["expires_at_iso"] = _iso(self.expires_at) if self.expires_at is not None else None
        return d


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _argv(action: str, addr: IPAddress) -> list[str]:
    binary = "ip6tables" if addr.version == 6 else "iptables"
    return [binary, action, "INPUT", "-s", str(addr), "-j", "DROP"]


def render_command(action: str, addr: IPAddress) -> str:
    return " ".join(_argv(action, addr))


class FirewallSimulator:
    def __init__(
        self,
        settings: Optional[Settings] = None,
        *,
        state_path: Optional[str] = None,
        log_path: Optional[str] = None,
        real: Optional[bool] = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.settings = s = settings or config.settings
        self.state_path = state_path if state_path is not None else s.firewall_state_file
        self.log_path = log_path if log_path is not None else s.firewall_log_file
        self.real = s.real_firewall if real is None else real
        self._clock = clock
        self._allow = parse_networks(s.firewall_allowlist) + parse_networks(s.internal_cidrs)
        self._lock = threading.RLock()
        self._rules: dict[str, FirewallRule] = {}
        self.commands: list[str] = []  # every rendered command, in order
        self._load()

    # --------------------------------------------------------------- guard

    def check_blockable(self, ip: str) -> IPAddress:
        """Validated address, or BlockRefused if the guard protects it."""
        try:
            addr = parse_ip(ip)
        except ValueError as exc:
            raise BlockRefused(f"invalid IP address: {ip!r}") from exc
        if is_private_or_special(addr):
            raise BlockRefused(f"{addr} is private/loopback/special and is never blocked")
        if any(addr in net for net in self._allow if net.version == addr.version):
            raise BlockRefused(f"{addr} is allowlisted")
        return addr

    # ----------------------------------------------------------------- API

    def block(self, ip: str, reason: str, ttl: Optional[float] = None) -> FirewallRule:
        return self.block_with_status(ip, reason, ttl)[0]

    def block_with_status(self, ip: str, reason: str,
                          ttl: Optional[float] = None) -> tuple[FirewallRule, bool]:
        """Idempotent block. Returns (rule, created). ``created`` is False if the IP was
        already blocked, in which case the existing rule is returned unchanged."""
        addr = self.check_blockable(ip)
        key = str(addr)
        ttl = self.settings.block_duration_s if ttl is None else ttl
        with self._lock:
            self._expire_locked()
            existing = self._rules.get(key)
            if existing is not None:
                return existing, False
            now = self._clock()
            rule = FirewallRule(
                ip=key,
                reason=reason,
                created_at=now,
                expires_at=(now + ttl) if ttl and ttl > 0 else None,
                command=render_command("-I", addr),
            )
            self._execute(_argv("-I", addr))
            self._rules[key] = rule
            self._record(rule.command)
            self._save()
            return rule, True

    def unblock(self, ip: str) -> bool:
        addr = parse_ip(ip)
        with self._lock:
            if str(addr) not in self._rules:
                return False
            self._remove_locked(addr)
            self._save()
            return True

    def is_blocked(self, ip: str) -> bool:
        try:
            key = str(parse_ip(ip))
        except ValueError:
            return False
        with self._lock:
            self._expire_locked()
            return key in self._rules

    def get_rule(self, ip: str) -> Optional[FirewallRule]:
        with self._lock:
            self._expire_locked()
            return self._rules.get(str(parse_ip(ip)))

    def list_rules(self) -> list[FirewallRule]:
        with self._lock:
            self._expire_locked()
            return sorted(self._rules.values(), key=lambda r: r.created_at)

    def expire(self) -> list[str]:
        """Remove TTL-expired rules now. Returns the unblocked IPs."""
        with self._lock:
            return self._expire_locked()

    # ----------------------------------------------------------- internals

    def _expire_locked(self) -> list[str]:
        now = self._clock()
        gone = [ip for ip, rule in self._rules.items() if rule.expired(now)]
        for ip in gone:
            self._remove_locked(parse_ip(ip))
        if gone:
            self._save()
        return gone

    def _remove_locked(self, addr: IPAddress) -> None:
        self._execute(_argv("-D", addr))
        del self._rules[str(addr)]
        self._record(render_command("-D", addr))

    def _execute(self, argv: list[str]) -> None:
        if not self.real:
            return
        # Real enforcement. argv is a fixed list built from a strictly validated
        # ipaddress object (never a shell string), so there is no injection surface.
        try:
            subprocess.run(argv, check=True, timeout=10, capture_output=True)  # nosec B603
        except (OSError, subprocess.SubprocessError) as exc:
            raise FirewallError(f"{argv[0]} {argv[1]} failed: {type(exc).__name__}") from exc

    def _record(self, command: str) -> None:
        self.commands.append(command)
        logger.info("firewall: %s", command)
        if not self.log_path:
            return
        try:
            _ensure_parent(self.log_path)
            with open(self.log_path, "a", encoding="utf-8") as fh:
                fh.write(f"{_iso(self._clock())} {command}\n")
        except OSError:
            logger.exception("could not write firewall command log %s", self.log_path)

    def _save(self) -> None:
        if not self.state_path:
            return
        payload = {"rules": [r.to_dict() for r in self._rules.values()]}
        try:
            _ensure_parent(self.state_path)
            directory = os.path.dirname(os.path.abspath(self.state_path))
            fd, tmp = tempfile.mkstemp(prefix=".fw-", suffix=".json", dir=directory)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, indent=2)
            os.replace(tmp, self.state_path)  # atomic: readers never see a partial file
        except OSError:
            logger.exception("could not persist firewall state to %s", self.state_path)

    def _load(self) -> None:
        if not self.state_path or not os.path.exists(self.state_path):
            return
        try:
            with open(self.state_path, encoding="utf-8") as fh:
                doc = json.load(fh)
            for item in doc.get("rules", []):
                addr = parse_ip(item["ip"])
                rule = FirewallRule(
                    ip=str(addr),
                    reason=str(item.get("reason", "")),
                    created_at=float(item["created_at"]),
                    expires_at=(float(item["expires_at"])
                                if item.get("expires_at") is not None else None),
                    command=render_command("-I", addr),
                )
                self._rules[rule.ip] = rule
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            logger.exception("ignoring unreadable firewall state file %s", self.state_path)
            self._rules.clear()


def _ensure_parent(path: str) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
