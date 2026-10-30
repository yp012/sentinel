"""Thread-safe incident store with optional SQLite persistence, plus the rolling
counters behind the dashboard KPIs.

An incident groups every alert for one (rule_id, src_ip) while it is active (open or
contained): a repeat alert, such as the SENTINEL-001 High -> Critical escalation,
raises the incident's severity and appends to its timeline instead of creating a
duplicate. Resolved / false-positive incidents are closed, so a later alert opens a
fresh one.

Memory is the source of truth. SQLite (stdlib ``sqlite3``, parameterized queries
only) is a write-through copy loaded at startup; a database error is logged and
never interrupts the pipeline. Counters and MTTD/MTTR aggregates cover the current
process only.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
import uuid
from collections import OrderedDict, deque
from dataclasses import dataclass, field, fields
from datetime import datetime, timezone
from typing import Any, Callable, Deque, Iterable, Literal, Mapping, Optional

from sentinel import config
from sentinel.config import Settings
from sentinel.soar.playbooks import ActionRecord, IncidentResponse

logger = logging.getLogger(__name__)

Status = Literal["open", "contained", "resolved", "false_positive"]
STATUSES: tuple[str, ...] = ("open", "contained", "resolved", "false_positive")
ACTIVE_STATUSES = frozenset(("open", "contained"))
SEVERITIES: tuple[str, ...] = ("Low", "Medium", "High", "Critical")
_SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}
_PRIORITY_RANK = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}

# Action outcomes that leave the threat contained (IP blocked or sessions revoked).
CONTAINING_ACTIONS = frozenset(("block_ip_firewall", "revoke_user_sessions",
                                "analyst_block_ip", "analyst_revoke_sessions"))
CONTAINED_STATUSES = frozenset(("success", "skipped_already_blocked"))

MAX_TIMELINE = 1000  # per incident; the oldest entries are dropped beyond this

_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS incidents ("
    " id TEXT PRIMARY KEY,"
    " rule_id TEXT NOT NULL,"
    " src_ip TEXT NOT NULL,"
    " severity TEXT NOT NULL,"
    " status TEXT NOT NULL,"
    " created_at REAL NOT NULL,"
    " updated_at REAL NOT NULL,"
    " doc TEXT NOT NULL)"
)
_UPSERT = (
    "INSERT INTO incidents (id, rule_id, src_ip, severity, status, created_at, updated_at, doc)"
    " VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
    " ON CONFLICT(id) DO UPDATE SET severity = excluded.severity, status = excluded.status,"
    " updated_at = excluded.updated_at, doc = excluded.doc"
)
_LOAD = "SELECT doc FROM incidents ORDER BY updated_at DESC LIMIT ?"


class IncidentNotFound(KeyError):
    """No incident with that id."""


def _iso(ts: Optional[float]) -> Optional[str]:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat() if ts is not None else None


def _ms(ns: Optional[int]) -> Optional[float]:
    return round(ns / 1e6, 3) if ns is not None else None


def is_containing(action: Mapping[str, Any]) -> bool:
    return action.get("name") in CONTAINING_ACTIONS and action.get("status") in CONTAINED_STATUSES


@dataclass
class Incident:
    id: str
    rule_id: str
    title: str
    mitre_technique: str
    severity: str
    src_ip: str
    user: str
    alert: dict[str, Any]            # latest alert, JSON-ready
    created_at: float                # wall clock, epoch seconds
    updated_at: float
    ingested_ns: int                 # monotonic: first alert's event ingestion
    detected_ns: int                 # monotonic: first alert produced by the engine
    status: str = "open"
    alert_ids: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    intel: Optional[dict[str, Any]] = None
    priority: Optional[str] = None
    tags: list[str] = field(default_factory=list)
    timeline: list[dict[str, Any]] = field(default_factory=list)
    timeline_dropped: int = 0
    contained_at: Optional[float] = None
    resolved_at: Optional[float] = None
    mttd_ns: Optional[int] = None    # detected_ns - ingested_ns of the first alert
    mttr_ns: Optional[int] = None    # automated block finished - ingestion (IncidentResponse)

    @property
    def key(self) -> tuple[str, str]:
        return merge_key(self.rule_id, self.src_ip, self.user)

    def append(self, entry: dict[str, Any]) -> None:
        self.timeline.append(entry)
        overflow = len(self.timeline) - MAX_TIMELINE
        if overflow > 0:
            del self.timeline[:overflow]
            self.timeline_dropped += overflow

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready snapshot. Lists are copied so callers never share mutable state."""
        doc = {f.name: getattr(self, f.name) for f in fields(self)}
        for name in ("alert_ids", "techniques", "tags", "timeline"):
            doc[name] = list(doc[name])
        doc["alert_count"] = len(self.alert_ids)
        doc["actions"] = [e for e in self.timeline if e.get("kind") == "action"]
        doc["mttd_ms"] = _ms(self.mttd_ns)
        doc["mttr_ms"] = _ms(self.mttr_ns)
        for name in ("created_at", "updated_at", "contained_at", "resolved_at"):
            doc[f"{name}_iso"] = _iso(doc[name])
        return doc

    @classmethod
    def from_dict(cls, doc: Mapping[str, Any]) -> "Incident":
        names = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in doc.items() if k in names})


def merge_key(rule_id: str, src_ip: str, user: str) -> tuple[str, str]:
    # Alerts without a source IP (badge-only anomalies) are grouped per user instead.
    return rule_id, (src_ip or f"user:{user}")


class _Aggregate:
    """Running mean of nanosecond durations."""

    __slots__ = ("count", "total", "min", "max", "last")

    def __init__(self) -> None:
        self.count = 0
        self.total = 0
        self.min: Optional[int] = None
        self.max: Optional[int] = None
        self.last: Optional[int] = None

    def add(self, value: int) -> None:
        self.count += 1
        self.total += value
        self.last = value
        self.min = value if self.min is None else min(self.min, value)
        self.max = value if self.max is None else max(self.max, value)

    def to_dict(self) -> dict[str, Any]:
        mean = self.total / self.count if self.count else None
        return {"count": self.count, "mean_ms": _ms(round(mean) if mean is not None else None),
                "min_ms": _ms(self.min), "max_ms": _ms(self.max), "last_ms": _ms(self.last)}


class IncidentStore:
    def __init__(
        self,
        db_path: Optional[str] = None,
        *,
        settings: Optional[Settings] = None,
        clock: Callable[[], float] = time.time,
        max_incidents: Optional[int] = None,
    ) -> None:
        self.settings = s = settings or config.settings
        self.db_path = s.db_path if db_path is None else db_path
        self._clock = clock
        self._max = s.store_max_incidents if max_incidents is None else max_incidents
        self._bucket_s = s.metrics_bucket_s if s.metrics_bucket_s > 0 else 1.0
        self._buckets = max(1, s.metrics_buckets)
        self._lock = threading.RLock()
        self._started = clock()

        self._incidents: OrderedDict[str, Incident] = OrderedDict()
        self._active: dict[tuple[str, str], str] = {}   # merge key -> incident id

        self.lines_received = 0
        self.lines_unparsed = 0
        self.ingest_errors = 0
        self.events_ingested = 0
        self.events_by_source: dict[str, int] = {}
        self.alerts_total = 0
        self.alerts_by_severity: dict[str, int] = dict.fromkeys(SEVERITIES, 0)
        self.alerts_by_technique: dict[str, int] = {}
        self.alerts_by_rule: dict[str, int] = {}
        self._series: Deque[list] = deque(maxlen=self._buckets)  # [bucket index, count]
        self.mttd = _Aggregate()
        self.mttr = _Aggregate()

        self._db: Optional[sqlite3.Connection] = None
        if self.db_path:
            self._open_db()

    # ------------------------------------------------------------ counters

    def record_event(self, source: str) -> None:
        """Hot path: one parsed event."""
        with self._lock:
            self.lines_received += 1
            self.events_ingested += 1
            self.events_by_source[source] = self.events_by_source.get(source, 0) + 1
            self._bump_series(1)

    def record_unparsed(self, n: int = 1) -> None:
        with self._lock:
            self.lines_received += n
            self.lines_unparsed += n

    def record_batch(self, by_source: Mapping[str, int], *, received: int, unparsed: int = 0,
                     errors: int = 0) -> None:
        """Flush a batch's counts in one lock acquisition."""
        parsed = sum(by_source.values())
        with self._lock:
            self.lines_received += received
            self.lines_unparsed += unparsed
            self.ingest_errors += errors
            self.events_ingested += parsed
            for source, n in by_source.items():
                self.events_by_source[source] = self.events_by_source.get(source, 0) + n
            if parsed:
                self._bump_series(parsed)

    def record_error(self) -> None:
        with self._lock:
            self.lines_received += 1
            self.ingest_errors += 1

    def _bump_series(self, n: int) -> None:
        idx = int(self._clock() // self._bucket_s)
        series = self._series
        if series and series[-1][0] == idx:
            series[-1][1] += n
        elif series and series[-1][0] > idx:  # wall clock stepped back: fold into latest
            series[-1][1] += n
        else:
            series.append([idx, n])

    # ----------------------------------------------------------- incidents

    def add_response(self, response: IncidentResponse, *, detected_ns: int) -> Incident:
        """Store one alert and its playbook results. Returns a snapshot of the incident
        it created or updated. ``detected_ns`` is when the engine produced the alert;
        ``alert.detected_at_ns`` is the ingestion time of the triggering event."""
        alert = response.alert
        now = self._clock()
        ingested_ns = alert.detected_at_ns
        mttd_ns = max(0, detected_ns - ingested_ns)
        mttr_ns = response.mttr_ns
        alert_doc = alert.model_dump(mode="json")
        intel = response.intel.to_dict() if response.intel is not None else None
        with self._lock:
            self.alerts_total += 1
            self.alerts_by_severity[alert.severity] = (
                self.alerts_by_severity.get(alert.severity, 0) + 1)
            technique = alert.mitre_technique
            self.alerts_by_technique[technique] = self.alerts_by_technique.get(technique, 0) + 1
            self.alerts_by_rule[alert.rule_id] = self.alerts_by_rule.get(alert.rule_id, 0) + 1
            self.mttd.add(mttd_ns)

            key = merge_key(alert.rule_id, alert.src_ip, alert.user)
            incident = self._incidents.get(self._active.get(key, ""))
            if incident is None or incident.status not in ACTIVE_STATUSES:
                incident = Incident(
                    id=f"INC-{uuid.uuid4().hex[:12]}",
                    rule_id=alert.rule_id, title=alert.title,
                    mitre_technique=technique, severity=alert.severity,
                    src_ip=alert.src_ip, user=alert.user, alert=alert_doc,
                    created_at=now, updated_at=now,
                    ingested_ns=ingested_ns, detected_ns=detected_ns, mttd_ns=mttd_ns,
                )
                self._incidents[incident.id] = incident
                self._active[key] = incident.id
                self._evict_locked()
            else:
                self._merge_alert_locked(incident, alert_doc)

            incident.alert_ids.append(alert.id)
            if technique not in incident.techniques:
                incident.techniques.append(technique)
            if intel is not None:
                incident.intel = intel
            if response.priority is not None and (
                    incident.priority is None
                    or _PRIORITY_RANK.get(response.priority, 9)
                    < _PRIORITY_RANK.get(incident.priority, 9)):
                incident.priority = response.priority
            for tag in response.tags:
                if tag not in incident.tags:
                    incident.tags.append(tag)

            at = _iso(now)
            incident.append({"kind": "alert", "at": at, "alert_id": alert.id,
                             "severity": alert.severity, "title": alert.title,
                             "mitre_technique": technique, "evidence": alert_doc["evidence"]})
            for action in response.actions:
                self._add_action_locked(incident, action, actor="soar", at=at, now=now,
                                        alert_id=alert.id)
            if mttr_ns is not None and incident.mttr_ns is None:
                incident.mttr_ns = mttr_ns
                self.mttr.add(mttr_ns)
            incident.updated_at = now
            self._persist_locked(incident)
            return Incident.from_dict(incident.to_dict())

    def _merge_alert_locked(self, incident: Incident, alert_doc: dict[str, Any]) -> None:
        new_sev = alert_doc["severity"]
        if _SEVERITY_RANK.get(new_sev, 0) > _SEVERITY_RANK.get(incident.severity, 0):
            incident.append({"kind": "severity", "at": _iso(self._clock()),
                             "from": incident.severity, "to": new_sev})
            incident.severity = new_sev
            incident.title = alert_doc["title"]
        incident.alert = alert_doc

    def _add_action_locked(self, incident: Incident, action: ActionRecord, *, actor: str,
                           at: Optional[str], now: float,
                           alert_id: Optional[str] = None) -> dict[str, Any]:
        entry = {"kind": "action", "at": at, "actor": actor, **action.to_dict(),
                 "duration_ms": _ms(action.duration_ns)}
        if alert_id is not None:
            entry["alert_id"] = alert_id
        incident.append(entry)
        if incident.status == "open" and is_containing(entry):
            self._set_status_locked(incident, "contained", now)
        return entry

    def record_analyst_actions(self, incident_id: str, actions: Iterable[ActionRecord],
                               note: str = "") -> Incident:
        """Append analyst-driven actions (one-click containment) to an incident."""
        now = self._clock()
        with self._lock:
            incident = self._require_locked(incident_id)
            at = _iso(now)
            if note:
                incident.append({"kind": "note", "at": at, "actor": "analyst", "note": note})
            for action in actions:
                self._add_action_locked(incident, action, actor="analyst", at=at, now=now)
            incident.updated_at = now
            self._persist_locked(incident)
            return Incident.from_dict(incident.to_dict())

    def set_status(self, incident_id: str, status: str, note: str = "",
                   actor: str = "analyst") -> Incident:
        if status not in STATUSES:
            raise ValueError(f"unknown status {status!r}")
        now = self._clock()
        with self._lock:
            incident = self._require_locked(incident_id)
            previous = incident.status
            self._set_status_locked(incident, status, now)
            if status in ACTIVE_STATUSES:
                # Re-opening: become the merge target again unless a newer incident took over.
                active_id = self._active.get(incident.key)
                active = self._incidents.get(active_id or "")
                if active is None or active.status not in ACTIVE_STATUSES:
                    self._active[incident.key] = incident.id
            incident.append({"kind": "status", "at": _iso(now), "actor": actor,
                             "from": previous, "to": status, "note": note})
            incident.updated_at = now
            self._persist_locked(incident)
            return Incident.from_dict(incident.to_dict())

    def _set_status_locked(self, incident: Incident, status: str, now: float) -> None:
        incident.status = status
        if status == "contained" and incident.contained_at is None:
            incident.contained_at = now
        if status in ("resolved", "false_positive"):
            incident.resolved_at = now
        elif status == "open":
            incident.resolved_at = None

    def get(self, incident_id: str) -> Optional[Incident]:
        with self._lock:
            incident = self._incidents.get(incident_id)
            return Incident.from_dict(incident.to_dict()) if incident is not None else None

    def get_dict(self, incident_id: str) -> Optional[dict[str, Any]]:
        with self._lock:
            incident = self._incidents.get(incident_id)
            return incident.to_dict() if incident is not None else None

    def list_incidents(self, *, severity: Optional[str] = None, status: Optional[str] = None,
                       limit: int = 200) -> list[dict[str, Any]]:
        """Newest first (by last update)."""
        with self._lock:
            matches = [i for i in self._incidents.values()
                       if (severity is None or i.severity == severity)
                       and (status is None or i.status == status)]
            matches.sort(key=lambda i: i.updated_at, reverse=True)
            return [i.to_dict() for i in matches[:max(0, limit)]]

    def __len__(self) -> int:
        with self._lock:
            return len(self._incidents)

    def _require_locked(self, incident_id: str) -> Incident:
        incident = self._incidents.get(incident_id)
        if incident is None:
            raise IncidentNotFound(incident_id)
        return incident

    def _evict_locked(self) -> None:
        while len(self._incidents) > self._max > 0:
            _, old = self._incidents.popitem(last=False)
            if self._active.get(old.key) == old.id:
                del self._active[old.key]

    # ------------------------------------------------------------- metrics

    def metrics(self) -> dict[str, Any]:
        now = self._clock()
        with self._lock:
            by_status = dict.fromkeys(STATUSES, 0)
            by_severity = dict.fromkeys(SEVERITIES, 0)
            for incident in self._incidents.values():
                by_status[incident.status] = by_status.get(incident.status, 0) + 1
                by_severity[incident.severity] = by_severity.get(incident.severity, 0) + 1
            return {
                "uptime_s": round(now - self._started, 3),
                "lines_received": self.lines_received,
                "lines_unparsed": self.lines_unparsed,
                "ingest_errors": self.ingest_errors,
                "events_ingested": self.events_ingested,
                "events_by_source": dict(self.events_by_source),
                "alerts_total": self.alerts_total,
                "alerts_by_severity": dict(self.alerts_by_severity),
                "alerts_by_technique": dict(self.alerts_by_technique),
                "alerts_by_rule": dict(self.alerts_by_rule),
                "incidents_total": len(self._incidents),
                "incidents_by_status": by_status,
                "incidents_by_severity": by_severity,
                "events_per_sec": self._series_locked(now),
                "mttd": self.mttd.to_dict(),
                "mttr": self.mttr.to_dict(),
            }

    def _series_locked(self, now: float) -> dict[str, Any]:
        width = self._bucket_s
        end = int(now // width)
        start = end - self._buckets + 1
        counts = {idx: n for idx, n in self._series if idx >= start}
        points = [{"t": _iso(idx * width), "count": counts.get(idx, 0),
                   "eps": round(counts.get(idx, 0) / width, 3)}
                  for idx in range(start, end + 1)]
        return {"bucket_s": width, "points": points}

    # --------------------------------------------------------- persistence

    def _open_db(self) -> None:
        try:
            parent = os.path.dirname(os.path.abspath(self.db_path))
            os.makedirs(parent, exist_ok=True)
            # One connection shared across threads; every use holds self._lock.
            self._db = sqlite3.connect(self.db_path, check_same_thread=False)
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute(_SCHEMA)
            self._db.commit()
            rows = self._db.execute(_LOAD, (max(self._max, 1),)).fetchall()
        except (OSError, sqlite3.Error):
            logger.exception("incident database %s unavailable; running in memory only",
                             self.db_path)
            self._db = None
            return
        for (doc,) in reversed(rows):  # oldest first, so OrderedDict order is preserved
            try:
                incident = Incident.from_dict(json.loads(doc))
            except (ValueError, TypeError):
                logger.warning("skipping unreadable incident row in %s", self.db_path)
                continue
            self._incidents[incident.id] = incident
            if incident.status in ACTIVE_STATUSES:
                self._active[incident.key] = incident.id

    def _persist_locked(self, incident: Incident) -> None:
        if self._db is None:
            return
        doc = json.dumps({f.name: getattr(incident, f.name) for f in fields(incident)},
                         default=str)
        try:
            self._db.execute(_UPSERT, (incident.id, incident.rule_id, incident.src_ip,
                                       incident.severity, incident.status,
                                       incident.created_at, incident.updated_at, doc))
            self._db.commit()
        except sqlite3.Error:
            logger.exception("could not persist incident %s", incident.id)

    def close(self) -> None:
        with self._lock:
            if self._db is not None:
                try:
                    self._db.close()
                except sqlite3.Error:
                    logger.exception("error closing incident database")
                self._db = None
