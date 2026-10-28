"""SOAR playbooks: a decorator-based registry plus a runner that executes the chain
configured for each rule (``Settings.playbook_chains``).

Timing uses the monotonic clock only. ``Alert.detected_at_ns`` is captured at event
ingestion, so ``IncidentResponse.mttr_ns`` (firewall rule executed minus ingestion)
is directly comparable with MTTD.
"""

from __future__ import annotations

import logging
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Optional

from sentinel import config
from sentinel.config import Settings
from sentinel.intel.abuseipdb import AbuseIPDBClient, IntelResult
from sentinel.models import Alert
from sentinel.soar.firewall import BlockRefused, FirewallSimulator
from sentinel.soar.sessions import SessionManager
from sentinel.soar.webhook import WebhookDispatcher

logger = logging.getLogger(__name__)

HIGH_PLUS = ("High", "Critical")
PRIORITY_BY_SEVERITY = {"Critical": "P1", "High": "P2", "Medium": "P3", "Low": "P4"}


@dataclass(frozen=True)
class ActionRecord:
    name: str
    status: str   # success | skipped_* | refused_safety_guard | outbox | error
    detail: str
    started_ns: int
    finished_ns: int
    data: dict[str, Any] = field(default_factory=dict)

    @property
    def duration_ns(self) -> int:
        return self.finished_ns - self.started_ns

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SOARServices:
    settings: Settings
    intel: AbuseIPDBClient
    firewall: FirewallSimulator
    sessions: SessionManager
    webhook: WebhookDispatcher

    @classmethod
    def create(cls, settings: Optional[Settings] = None) -> "SOARServices":
        s = settings or config.settings
        return cls(s, AbuseIPDBClient(s), FirewallSimulator(s), SessionManager(),
                   WebhookDispatcher(s))


@dataclass
class PlaybookContext:
    alert: Alert
    services: SOARServices
    intel: Optional[IntelResult] = None
    priority: Optional[str] = None
    tags: list[str] = field(default_factory=list)
    actions: list[ActionRecord] = field(default_factory=list)


PlaybookFunc = Callable[[PlaybookContext], ActionRecord]
PLAYBOOKS: dict[str, PlaybookFunc] = {}


def playbook(name: str) -> Callable[[PlaybookFunc], PlaybookFunc]:
    """Register a playbook under ``name``."""
    def register(func: PlaybookFunc) -> PlaybookFunc:
        if name in PLAYBOOKS:
            raise ValueError(f"playbook {name!r} already registered")
        PLAYBOOKS[name] = func
        return func
    return register


def _record(name: str, started_ns: int, status: str, detail: str, **data: Any) -> ActionRecord:
    return ActionRecord(name, status, detail, started_ns, time.monotonic_ns(), data)


# ---------------------------------------------------------------- playbooks

@playbook("enrich_ip_reputation")
def enrich_ip_reputation(ctx: PlaybookContext) -> ActionRecord:
    started = time.monotonic_ns()
    ip = ctx.alert.src_ip
    if not ip:
        return _record("enrich_ip_reputation", started, "skipped_no_ip", "alert has no src_ip")
    try:
        ctx.intel = ctx.services.intel.score(ip)
    except ValueError:
        return _record("enrich_ip_reputation", started, "skipped_invalid_ip", f"bad IP {ip!r}")
    return _record("enrich_ip_reputation", started, "success",
                   f"{ip} score={ctx.intel.score} ({ctx.intel.source})", **ctx.intel.to_dict())


@playbook("block_ip_firewall")
def block_ip_firewall(ctx: PlaybookContext) -> ActionRecord:
    started = time.monotonic_ns()
    alert, s = ctx.alert, ctx.services.settings
    ip = alert.src_ip
    if not ip:
        return _record("block_ip_firewall", started, "skipped_no_ip", "alert has no src_ip")
    score = ctx.intel.score if ctx.intel is not None else None
    if alert.severity not in HIGH_PLUS and (score is None or score < s.abuseipdb_block_score):
        return _record("block_ip_firewall", started, "skipped_below_threshold",
                       f"severity={alert.severity} score={score} < {s.abuseipdb_block_score}",
                       score=score)
    try:
        rule, created = ctx.services.firewall.block_with_status(
            ip, reason=f"{alert.rule_id} {alert.title} (alert {alert.id})",
            ttl=s.block_duration_s)
    except BlockRefused as exc:
        return _record("block_ip_firewall", started, "refused_safety_guard", str(exc))
    if not created:
        return _record("block_ip_firewall", started, "skipped_already_blocked",
                       f"{ip} already blocked: {rule.command}", **rule.to_dict())
    # finished_ns is taken right after the rule executed: the MTTR end point.
    return _record("block_ip_firewall", started, "success", rule.command, **rule.to_dict())


@playbook("revoke_user_sessions")
def revoke_user_sessions(ctx: PlaybookContext) -> ActionRecord:
    started = time.monotonic_ns()
    alert = ctx.alert
    if not alert.mitre_technique.startswith("T1078"):
        return _record("revoke_user_sessions", started, "skipped_not_applicable",
                       f"{alert.mitre_technique} is not a valid-accounts technique")
    sessions = ctx.services.sessions
    reason = f"{alert.rule_id} alert {alert.id}"
    revoked = sessions.revoke_user(alert.user, reason) if alert.user else []
    if alert.src_ip:
        revoked += sessions.revoke_ip(alert.src_ip, reason)
    if revoked:
        ids = sorted({s.id for s in revoked})
        return _record("revoke_user_sessions", started, "success",
                       f"revoked {len(ids)} session(s)", sessions=ids)
    status = ("skipped_already_revoked"
              if sessions.was_revoked(user=alert.user or None, ip=alert.src_ip or None)
              else "skipped_no_sessions")
    return _record("revoke_user_sessions", started, status, "no active sessions to revoke")


@playbook("escalate_critical")
def escalate_critical(ctx: PlaybookContext) -> ActionRecord:
    started = time.monotonic_ns()
    severity = ctx.alert.severity
    ctx.priority = PRIORITY_BY_SEVERITY.get(severity, "P4")
    if severity != "Critical":
        return _record("escalate_critical", started, "skipped_not_critical",
                       f"priority {ctx.priority}", priority=ctx.priority)
    for tag in ("escalated", "needs-analyst", ctx.alert.rule_id):
        if tag not in ctx.tags:
            ctx.tags.append(tag)
    return _record("escalate_critical", started, "success",
                   f"incident escalated to analyst as {ctx.priority}",
                   priority=ctx.priority, tags=list(ctx.tags))


@playbook("dispatch_webhook_alert")
def dispatch_webhook_alert(ctx: PlaybookContext) -> ActionRecord:
    started = time.monotonic_ns()
    actions = [a.to_dict() for a in ctx.actions]
    intel = ctx.intel.to_dict() if ctx.intel is not None else None
    result = ctx.services.webhook.dispatch(ctx.alert, intel, actions)
    status = {"webhook": "success", "outbox": "outbox"}.get(result.channel, "error")
    return _record("dispatch_webhook_alert", started, status, result.detail,
                   channel=result.channel)


# ------------------------------------------------------------------- runner

@dataclass
class IncidentResponse:
    alert: Alert
    intel: Optional[IntelResult]
    priority: Optional[str]
    tags: list[str]
    actions: list[ActionRecord]

    def action(self, name: str) -> Optional[ActionRecord]:
        return next((a for a in self.actions if a.name == name), None)

    @property
    def mttr_ns(self) -> Optional[int]:
        """Event ingestion -> firewall rule executed. None if this response blocked nothing."""
        block = self.action("block_ip_firewall")
        if block is None or block.status != "success":
            return None
        return block.finished_ns - self.alert.detected_at_ns


class PlaybookRunner:
    def __init__(self, services: Optional[SOARServices] = None,
                 chains: Optional[dict[str, tuple[str, ...]]] = None) -> None:
        self.services = services or SOARServices.create()
        self.chains = chains if chains is not None else self.services.settings.playbook_chains

    def chain_for(self, rule_id: str) -> tuple[str, ...]:
        return tuple(self.chains.get(rule_id) or self.chains.get("default") or ())

    def run(self, alert: Alert) -> IncidentResponse:
        """Execute the rule's chain in order. A failing playbook is recorded as
        ``error`` and the chain continues. Never raises."""
        ctx = PlaybookContext(alert=alert, services=self.services)
        for name in self.chain_for(alert.rule_id):
            started = time.monotonic_ns()
            func = PLAYBOOKS.get(name)
            if func is None:
                ctx.actions.append(_record(name, started, "error", "unknown playbook"))
                continue
            try:
                ctx.actions.append(func(ctx))
            except Exception as exc:
                logger.exception("playbook %s failed for alert %s", name, alert.id)
                ctx.actions.append(_record(name, started, "error", type(exc).__name__))
        return IncidentResponse(alert, ctx.intel, ctx.priority, ctx.tags, ctx.actions)
