"""All tunables in one place. Every value can be overridden by an env var of the same name."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from exc


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number, got {raw!r}") from exc


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_str(name: str, default: str) -> str:
    return os.getenv(name, default)


def _env_list(name: str, default: str) -> tuple[str, ...]:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        raw = default
    return tuple(part.strip() for part in raw.split(",") if part.strip())


@dataclass(frozen=True)
class Settings:
    # Shared detector state limits: max events kept per key, max keys per detector.
    window_max_events_per_key: int = field(
        default_factory=lambda: _env_int("SENTINEL_WINDOW_MAX_EVENTS_PER_KEY", 1000))
    window_max_keys: int = field(
        default_factory=lambda: _env_int("SENTINEL_WINDOW_MAX_KEYS", 100_000))
    # Minimum gap between repeat alerts for the same key (IP / user).
    alert_cooldown_s: int = field(
        default_factory=lambda: _env_int("SENTINEL_ALERT_COOLDOWN_S", 300))

    # SENTINEL-001 SSH brute force: fires when failures from one IP exceed the threshold.
    ssh_bruteforce_threshold: int = field(
        default_factory=lambda: _env_int("SSH_BRUTEFORCE_THRESHOLD", 5))
    ssh_bruteforce_critical: int = field(
        default_factory=lambda: _env_int("SSH_BRUTEFORCE_CRITICAL", 20))
    ssh_bruteforce_window_s: int = field(
        default_factory=lambda: _env_int("SSH_BRUTEFORCE_WINDOW_S", 60))
    # "Invalid user X" + "Failed password for invalid user X" within this gap = one attempt.
    ssh_invalid_user_dedupe_s: float = field(
        default_factory=lambda: _env_float("SSH_INVALID_USER_DEDUPE_S", 1.0))

    # SENTINEL-002 web/VPN login brute force and password spraying.
    http_login_fail_threshold: int = field(
        default_factory=lambda: _env_int("HTTP_LOGIN_FAIL_THRESHOLD", 5))
    http_login_fail_critical: int = field(
        default_factory=lambda: _env_int("HTTP_LOGIN_FAIL_CRITICAL", 20))
    http_login_fail_window_s: int = field(
        default_factory=lambda: _env_int("HTTP_LOGIN_FAIL_WINDOW_S", 60))
    # This many distinct usernames from one IP in the window = spraying (T1110.003).
    web_spray_distinct_users: int = field(
        default_factory=lambda: _env_int("WEB_SPRAY_DISTINCT_USERS", 3))

    # SENTINEL-003 SQL injection: minimum heuristic score to alert.
    sqli_score_threshold: int = field(
        default_factory=lambda: _env_int("SQLI_SCORE_THRESHOLD", 4))

    # SENTINEL-005 physical/digital anomaly.
    # a) VPN from outside while badged "in" at the secure facility within this window.
    onsite_window_s: int = field(
        default_factory=lambda: _env_int("SENTINEL_ONSITE_WINDOW_S", 8 * 3600))
    # b) On-prem SSH with no granted badge-in at the facility within this lookback.
    badge_lookback_s: int = field(
        default_factory=lambda: _env_int("SENTINEL_BADGE_LOOKBACK_S", 12 * 3600))
    secure_facility: str = field(
        default_factory=lambda: _env_str("SENTINEL_SECURE_FACILITY", "HQ"))
    internal_cidrs: tuple[str, ...] = field(
        default_factory=lambda: _env_list(
            "SENTINEL_INTERNAL_CIDRS", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"))
    # Only apply rule (b) to users who have ever badged (skips service accounts like root).
    require_known_badge: bool = field(
        default_factory=lambda: _env_bool("SENTINEL_REQUIRE_KNOWN_BADGE", True))

    # SENTINEL-006 success after brute force: how long a tripped IP stays suspicious.
    success_after_bf_window_s: int = field(
        default_factory=lambda: _env_int("SUCCESS_AFTER_BF_WINDOW_S", 3600))

    # Threat intel.
    abuseipdb_api_key: str = field(
        default_factory=lambda: _env_str("ABUSEIPDB_API_KEY", ""), repr=False)
    # The block_ip_firewall playbook blocks when intel score >= this (or severity High+).
    abuseipdb_block_score: int = field(
        default_factory=lambda: _env_int("ABUSEIPDB_BLOCK_SCORE", 75))
    abuseipdb_timeout_s: float = field(
        default_factory=lambda: _env_float("ABUSEIPDB_TIMEOUT_S", 3.0))
    abuseipdb_retries: int = field(
        default_factory=lambda: _env_int("ABUSEIPDB_RETRIES", 1))
    abuseipdb_cache_ttl_s: int = field(
        default_factory=lambda: _env_int("ABUSEIPDB_CACHE_TTL_S", 3600))
    abuseipdb_max_age_days: int = field(
        default_factory=lambda: _env_int("ABUSEIPDB_MAX_AGE_DAYS", 90))

    # Response. Real iptables only when explicitly enabled.
    real_firewall: bool = field(
        default_factory=lambda: _env_bool("SENTINEL_REAL_FIREWALL", False))
    block_duration_s: int = field(
        default_factory=lambda: _env_int("SENTINEL_BLOCK_DURATION_S", 3600))
    data_dir: str = field(
        default_factory=lambda: _env_str("SENTINEL_DATA_DIR", "data"))
    # Empty path = default file under data_dir (see the *_file properties).
    firewall_state_path: str = field(
        default_factory=lambda: _env_str("SENTINEL_FIREWALL_STATE_PATH", ""))
    firewall_log_path: str = field(
        default_factory=lambda: _env_str("SENTINEL_FIREWALL_LOG_PATH", ""))
    # IPs/CIDRs the firewall must never block (on top of private/loopback ranges).
    firewall_allowlist: tuple[str, ...] = field(
        default_factory=lambda: _env_list("SENTINEL_FIREWALL_ALLOWLIST", ""))

    # Alert webhook. Unset URL = write to the JSONL outbox instead.
    webhook_url: str = field(
        default_factory=lambda: _env_str("WEBHOOK_URL", ""), repr=False)
    webhook_timeout_s: float = field(
        default_factory=lambda: _env_float("WEBHOOK_TIMEOUT_S", 3.0))
    webhook_retries: int = field(
        default_factory=lambda: _env_int("WEBHOOK_RETRIES", 1))
    webhook_outbox_path: str = field(
        default_factory=lambda: _env_str("WEBHOOK_OUTBOX_PATH", ""))

    # Ordered SOAR playbook chain per rule. Override (merged per rule) with JSON, e.g.
    # SENTINEL_PLAYBOOK_CHAINS='{"SENTINEL-003": ["enrich_ip_reputation"]}'
    playbook_chains: dict[str, tuple[str, ...]] = field(
        default_factory=lambda: _playbook_chains())

    # Live log following.
    tail_poll_interval_s: float = field(
        default_factory=lambda: _env_float("SENTINEL_TAIL_POLL_INTERVAL_S", 0.25))

    @property
    def firewall_state_file(self) -> str:
        return self.firewall_state_path or os.path.join(self.data_dir, "firewall_rules.json")

    @property
    def firewall_log_file(self) -> str:
        return self.firewall_log_path or os.path.join(self.data_dir, "firewall_commands.log")

    @property
    def webhook_outbox_file(self) -> str:
        return self.webhook_outbox_path or os.path.join(self.data_dir, "webhook_outbox.jsonl")


_NETWORK_CHAIN = ("enrich_ip_reputation", "block_ip_firewall", "escalate_critical",
                  "dispatch_webhook_alert")
_IDENTITY_CHAIN = ("enrich_ip_reputation", "block_ip_firewall", "revoke_user_sessions",
                   "escalate_critical", "dispatch_webhook_alert")

DEFAULT_PLAYBOOK_CHAINS: dict[str, tuple[str, ...]] = {
    "SENTINEL-001": _NETWORK_CHAIN,
    "SENTINEL-002": _NETWORK_CHAIN,
    "SENTINEL-003": _NETWORK_CHAIN,
    "SENTINEL-004": _NETWORK_CHAIN,
    "SENTINEL-005": _IDENTITY_CHAIN,
    "SENTINEL-006": _IDENTITY_CHAIN,
    # Any rule not listed above.
    "default": ("enrich_ip_reputation", "escalate_critical", "dispatch_webhook_alert"),
}


def _playbook_chains() -> dict[str, tuple[str, ...]]:
    chains = dict(DEFAULT_PLAYBOOK_CHAINS)
    raw = os.getenv("SENTINEL_PLAYBOOK_CHAINS", "").strip()
    if not raw:
        return chains
    try:
        override = json.loads(raw)
    except ValueError as exc:
        raise ValueError("SENTINEL_PLAYBOOK_CHAINS must be a JSON object") from exc
    if not isinstance(override, dict) or not all(
            isinstance(v, list) and all(isinstance(n, str) for n in v)
            for v in override.values()):
        raise ValueError("SENTINEL_PLAYBOOK_CHAINS must map rule ids to lists of names")
    chains.update({str(k): tuple(v) for k, v in override.items()})
    return chains


def get_settings() -> Settings:
    """Build a fresh Settings from the current environment (handy in tests)."""
    return Settings()


settings = get_settings()
