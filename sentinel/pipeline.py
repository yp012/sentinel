"""Ingestion pipeline: parse -> detect -> respond -> store.

Timing uses the monotonic clock. ``Pipeline.ingest`` reads it once at entry, before
parsing, and stamps the value on ``Event.ingested_ns``; detectors copy that onto
``Alert.detected_at_ns``. The store then derives:

* MTTD = when the engine returned the alert - ingestion
* MTTR = ``block_ip_firewall`` finished - ingestion (``IncidentResponse.mttr_ns``)

Only one thread runs the (stateful) detectors at a time; playbooks run outside that
lock, since every SOAR service and the store are thread-safe.
"""

from __future__ import annotations

import dataclasses
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Iterator, Optional, Sequence, Union

from sentinel import config
from sentinel.config import Settings, settings
from sentinel.detection.engine import DetectionEngine
from sentinel.intel.abuseipdb import AbuseIPDBClient
from sentinel.models import Event
from sentinel.parsers import parse_any
from sentinel.soar.firewall import BlockRefused, FirewallError, FirewallSimulator
from sentinel.soar.playbooks import ActionRecord, PlaybookRunner, SOARServices
from sentinel.soar.sessions import SessionManager
from sentinel.soar.webhook import WebhookDispatcher
from sentinel.store import CONTAINED_STATUSES, IncidentNotFound, IncidentStore

logger = logging.getLogger(__name__)

Ingestible = Union[str, Event]
_NONE: tuple[str, ...] = ()


@dataclass
class BatchResult:
    received: int = 0
    parsed: int = 0
    unparsed: int = 0
    alerts: int = 0
    incidents: list[str] = field(default_factory=list)   # ids created or updated, in order
    errors: list[dict[str, Any]] = field(default_factory=list)  # {"index", "error"}

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


class Pipeline:
    """Wires parser, detection engine, playbooks and store together.

    Every dependency can be injected. ``data_dir`` relocates the firewall state and
    command log and the webhook outbox (and is the base for nothing else), so tests
    and the benchmark can run entirely inside a temp directory.
    """

    def __init__(
        self,
        settings: Optional[Settings] = None,
        *,
        engine: Optional[DetectionEngine] = None,
        intel: Optional[AbuseIPDBClient] = None,
        firewall: Optional[FirewallSimulator] = None,
        sessions: Optional[SessionManager] = None,
        webhook: Optional[WebhookDispatcher] = None,
        store: Optional[IncidentStore] = None,
        runner: Optional[PlaybookRunner] = None,
        parser: Callable[[str], Optional[Event]] = parse_any,
        data_dir: Optional[str] = None,
        db_path: Optional[str] = None,
        log_paths: Optional[Sequence[str]] = None,
    ) -> None:
        s = settings or config.settings
        if data_dir is not None:
            s = dataclasses.replace(s, data_dir=data_dir, firewall_state_path="",
                                    firewall_log_path="", webhook_outbox_path="")
        self.settings = s
        # ``is None`` rather than ``or``: an empty store (``__len__`` == 0) is falsy.
        self.engine = engine if engine is not None else DetectionEngine(settings=s)
        if runner is None:
            runner = PlaybookRunner(SOARServices(
                s,
                intel if intel is not None else AbuseIPDBClient(s),
                firewall if firewall is not None else FirewallSimulator(s),
                sessions if sessions is not None else SessionManager(),
                webhook if webhook is not None else WebhookDispatcher(s),
            ))
        self.runner = runner
        self.services = runner.services
        self.store = store if store is not None else IncidentStore(db_path, settings=s)
        self.log_paths: tuple[str, ...] = (
            tuple(log_paths) if log_paths is not None else s.log_paths)
        self._parse = parser
        self._detect_lock = threading.Lock()
        self._stop = threading.Event()
        self._tailers: list[threading.Thread] = []

    @property
    def firewall(self) -> FirewallSimulator:
        return self.services.firewall

    @property
    def sessions(self) -> SessionManager:
        return self.services.sessions

    @property
    def intel(self) -> AbuseIPDBClient:
        return self.services.intel

    # -------------------------------------------------------------- ingest

    def ingest(self, item: Ingestible) -> tuple[str, ...]:
        """Process one raw line or Event. Returns the ids of incidents created or
        updated (usually none). Unparseable lines are counted and ignored."""
        t_ingest_ns = time.monotonic_ns()
        event = self._to_event(item)
        if event is None:
            self.store.record_unparsed()
            return _NONE
        event.ingested_ns = t_ingest_ns
        self.store.record_event(event.source)
        return self._detect_and_respond(event)

    def ingest_batch(self, items: Iterable[Ingestible]) -> BatchResult:
        """Process many lines/Events. A failure on one item is recorded in
        ``errors`` and the batch carries on."""
        result = BatchResult()
        by_source: dict[str, int] = {}
        for index, item in enumerate(items):
            result.received += 1
            t_ingest_ns = time.monotonic_ns()
            try:
                event = self._to_event(item)
                if event is None:
                    result.unparsed += 1
                    continue
                event.ingested_ns = t_ingest_ns
                result.parsed += 1
                by_source[event.source] = by_source.get(event.source, 0) + 1
                touched = self._detect_and_respond(event)
            except Exception as exc:
                # The line itself is attacker-controlled: log only where and what failed.
                logger.warning("ingest failed for batch item %d: %s", index,
                               type(exc).__name__, exc_info=True)
                result.errors.append({"index": index, "error": type(exc).__name__})
                continue
            if touched:
                result.alerts += len(touched)
                result.incidents.extend(touched)
        result.incidents = list(dict.fromkeys(result.incidents))
        self.store.record_batch(by_source, received=result.received,
                                unparsed=result.unparsed, errors=len(result.errors))
        return result

    def _to_event(self, item: Ingestible) -> Optional[Event]:
        if isinstance(item, str):
            return self._parse(item)
        if isinstance(item, Event):
            return item
        raise TypeError(f"expected a log line or Event, got {type(item).__name__}")

    def _detect_and_respond(self, event: Event) -> tuple[str, ...]:
        with self._detect_lock:
            alerts = self.engine.process(event)
        if not alerts:
            return _NONE
        detected_ns = time.monotonic_ns()
        ids = []
        for alert in alerts:
            response = self.runner.run(alert)
            ids.append(self.store.add_response(response, detected_ns=detected_ns).id)
        return tuple(ids)

    # ---------------------------------------------------------- containment

    def contain(self, incident_id: str, *, note: str = "",
                revoke_sessions: bool = True) -> dict[str, Any]:
        """Analyst one-click containment: block the source IP, revoke sessions and log
        both on the incident. The firewall safety guard still applies; a refused or
        failed block is reported in ``block`` and ``blocked`` is False.
        Raises IncidentNotFound."""
        incident = self.store.get(incident_id)
        if incident is None:
            raise IncidentNotFound(incident_id)
        block = self._analyst_block(incident.id, incident.rule_id, incident.src_ip)
        actions = [block]
        revoke = None
        if revoke_sessions:
            revoke = self._analyst_revoke(incident.id, incident.user, incident.src_ip)
            actions.append(revoke)
        updated = self.store.record_analyst_actions(
            incident.id, actions, note=note or "one-click containment")
        return {
            "incident": updated.to_dict(),
            "blocked": block.status in CONTAINED_STATUSES,
            "block": block.to_dict(),
            "sessions": revoke.to_dict() if revoke is not None else None,
            "contained": updated.status == "contained",
        }

    def _analyst_block(self, incident_id: str, rule_id: str, ip: str) -> ActionRecord:
        started = time.monotonic_ns()
        name = "analyst_block_ip"
        if not ip:
            return ActionRecord(name, "skipped_no_ip", "incident has no source IP",
                                started, time.monotonic_ns())
        try:
            rule, created = self.firewall.block_with_status(
                ip, reason=f"analyst containment of {incident_id} ({rule_id})",
                ttl=self.settings.block_duration_s)
        except BlockRefused as exc:
            return ActionRecord(name, "refused_safety_guard", str(exc), started,
                                time.monotonic_ns())
        except FirewallError as exc:
            return ActionRecord(name, "error", str(exc), started, time.monotonic_ns())
        status = "success" if created else "skipped_already_blocked"
        return ActionRecord(name, status, rule.command, started, time.monotonic_ns(),
                            rule.to_dict())

    def _analyst_revoke(self, incident_id: str, user: str, ip: str) -> ActionRecord:
        started = time.monotonic_ns()
        name = "analyst_revoke_sessions"
        reason = f"analyst containment of {incident_id}"
        revoked = self.sessions.revoke_user(user, reason) if user else []
        if ip:
            revoked += self.sessions.revoke_ip(ip, reason)
        if revoked:
            ids = sorted({s.id for s in revoked})
            return ActionRecord(name, "success", f"revoked {len(ids)} session(s)", started,
                                time.monotonic_ns(), {"sessions": ids})
        status = ("skipped_already_revoked"
                  if self.sessions.was_revoked(user=user or None, ip=ip or None)
                  else "skipped_no_sessions")
        return ActionRecord(name, status, "no active sessions to revoke", started,
                            time.monotonic_ns())

    # ------------------------------------------------------------- tailing

    def start_tailing(self, paths: Optional[Sequence[str]] = None, *,
                      from_start: Optional[bool] = None) -> list[str]:
        """Follow each path in a daemon thread. Returns the paths now being followed."""
        paths = list(self.log_paths if paths is None else paths)
        start = self.settings.tail_from_start if from_start is None else from_start
        self._stop.clear()
        followed = []
        for path in paths:
            thread = threading.Thread(target=self._tail_loop, args=(path, start),
                                      name=f"tail:{os.path.basename(path)}", daemon=True)
            thread.start()
            self._tailers.append(thread)
            followed.append(path)
        return followed

    @property
    def tailing(self) -> bool:
        return any(t.is_alive() for t in self._tailers)

    def _tail_loop(self, path: str, from_start: bool) -> None:
        logger.info("following %s", path)
        try:
            for line in tail_file(path, from_start=from_start,
                                  poll_interval=self.settings.tail_poll_interval_s,
                                  stop_event=self._stop):
                try:
                    self.ingest(line)
                except Exception:
                    self.store.record_error()
                    logger.exception("pipeline failed on a line from %s", path)
        except Exception:
            logger.exception("tailing %s stopped unexpectedly", path)

    def stop_tailing(self, timeout: float = 5.0) -> None:
        self._stop.set()
        for thread in self._tailers:
            thread.join(timeout)
        self._tailers = [t for t in self._tailers if t.is_alive()]

    def close(self) -> None:
        self.stop_tailing()
        self.store.close()


def tail_file(
    path: str,
    *,
    from_start: bool = False,
    poll_interval: Optional[float] = None,
    stop_event: Optional[threading.Event] = None,
) -> Iterator[str]:
    """Follow ``path`` like ``tail -F`` using plain polling.

    Yields complete lines without the trailing newline. Survives the file not
    existing yet, truncation (``copytruncate``) and rotation (new inode). Returns
    once ``stop_event`` is set and no unread data remains.
    """
    interval = settings.tail_poll_interval_s if poll_interval is None else poll_interval
    stop = stop_event or threading.Event()
    fh = None
    inode = None
    buf = b""
    first_open = True

    try:
        while True:
            if fh is None:
                try:
                    fh = open(path, "rb")
                except FileNotFoundError:
                    if stop.is_set():
                        return
                    time.sleep(interval)
                    continue
                inode = os.fstat(fh.fileno()).st_ino
                if first_open and not from_start:
                    fh.seek(0, os.SEEK_END)
                first_open = False
                buf = b""

            chunk = fh.read()
            if chunk:
                buf += chunk
                *lines, buf = buf.split(b"\n")
                for ln in lines:
                    yield ln.rstrip(b"\r").decode("utf-8", errors="replace")
                continue

            # No new data: check for truncation or rotation before sleeping.
            try:
                st = os.stat(path)
            except FileNotFoundError:
                st = None
            if st is not None and st.st_ino != inode:
                fh.close()
                fh = None
                continue
            if st is not None and st.st_size < fh.tell():
                fh.seek(0)
                buf = b""
                continue

            if stop.is_set():
                return
            time.sleep(interval)
    finally:
        if fh is not None:
            fh.close()
