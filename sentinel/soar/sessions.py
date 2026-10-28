"""Simulated active-session store (SSH/VPN/web) with revocation."""

from __future__ import annotations

import itertools
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

SAMPLE_SESSIONS: tuple[tuple[str, str, str], ...] = (
    ("alice", "10.0.1.15", "vpn"),
    ("alice", "10.0.1.15", "ssh"),
    ("bob", "10.0.2.22", "vpn"),
    ("carol", "192.168.10.5", "web"),
    ("root", "10.0.5.10", "ssh"),
    ("svc-backup", "10.0.9.9", "ssh"),
)


@dataclass
class Session:
    id: str
    user: str
    src_ip: str
    kind: str
    started_at: datetime
    active: bool = True
    revoked_at: Optional[datetime] = None
    revoked_reason: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id, "user": self.user, "src_ip": self.src_ip, "kind": self.kind,
            "started_at": self.started_at.isoformat(), "active": self.active,
            "revoked_at": self.revoked_at.isoformat() if self.revoked_at else None,
            "revoked_reason": self.revoked_reason,
        }


class SessionManager:
    """Thread-safe in-memory sessions. ``seed=True`` loads SAMPLE_SESSIONS."""

    def __init__(self, seed: bool = True) -> None:
        self._sessions: dict[str, Session] = {}
        self._ids = itertools.count(1)
        self._lock = threading.RLock()
        self._revoked_users: set[str] = set()
        self._revoked_ips: set[str] = set()
        if seed:
            for user, ip, kind in SAMPLE_SESSIONS:
                self.add_session(user, ip, kind)

    def add_session(self, user: str, src_ip: str, kind: str = "ssh") -> Session:
        with self._lock:
            sid = f"sess-{next(self._ids):05d}"
            session = Session(sid, user, src_ip, kind, datetime.now(timezone.utc))
            self._sessions[sid] = session
            return session

    def active_sessions(self, user: Optional[str] = None,
                        src_ip: Optional[str] = None) -> list[Session]:
        with self._lock:
            return [s for s in self._sessions.values() if s.active
                    and (user is None or s.user == user)
                    and (src_ip is None or s.src_ip == src_ip)]

    def revoke_user(self, user: str, reason: str = "") -> list[Session]:
        """Revoke all active sessions of ``user``. Returns only newly revoked sessions."""
        with self._lock:
            self._revoked_users.add(user)
            return self._revoke(self.active_sessions(user=user), reason)

    def revoke_ip(self, ip: str, reason: str = "") -> list[Session]:
        with self._lock:
            self._revoked_ips.add(ip)
            return self._revoke(self.active_sessions(src_ip=ip), reason)

    def was_revoked(self, *, user: Optional[str] = None, ip: Optional[str] = None) -> bool:
        with self._lock:
            return (user is not None and user in self._revoked_users) or \
                   (ip is not None and ip in self._revoked_ips)

    def _revoke(self, sessions: list[Session], reason: str) -> list[Session]:
        now = datetime.now(timezone.utc)
        for s in sessions:
            s.active = False
            s.revoked_at = now
            s.revoked_reason = reason
        return sessions
