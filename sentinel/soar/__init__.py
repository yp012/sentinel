"""Automated response: firewall, sessions, webhook and playbooks."""

from sentinel.soar.firewall import BlockRefused, FirewallError, FirewallRule, FirewallSimulator
from sentinel.soar.playbooks import (
    PLAYBOOKS, ActionRecord, IncidentResponse, PlaybookRunner, SOARServices, playbook,
)
from sentinel.soar.sessions import SessionManager
from sentinel.soar.webhook import DispatchResult, WebhookDispatcher, build_payload

__all__ = [
    "PLAYBOOKS", "ActionRecord", "BlockRefused", "DispatchResult", "FirewallError",
    "FirewallRule", "FirewallSimulator", "IncidentResponse", "PlaybookRunner",
    "SOARServices", "SessionManager", "WebhookDispatcher", "build_payload", "playbook",
]
