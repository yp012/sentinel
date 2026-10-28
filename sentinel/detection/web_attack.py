"""Web exploitation rules: SENTINEL-003 (SQL injection), SENTINEL-004 (path traversal)."""

from __future__ import annotations

import re
from typing import Optional
from urllib.parse import unquote, unquote_plus

from sentinel.detection.base import Detector
from sentinel.models import Alert, Event, Severity

# (name, weight, pattern) applied to the normalized, lower-cased URI.
# Single weak signals (a bare "select", a "-- ") stay below the default threshold of 4.
SQLI_SIGNALS: tuple[tuple[str, int, re.Pattern[str]], ...] = tuple(
    (name, weight, re.compile(pattern)) for name, weight, pattern in (
        ("union_select", 5, r"\bunion(?:\s+all|\s+distinct)?\s+select\b"),
        ("quoted_tautology", 5,
         r"['\"]\s*(?:or|\|\|)\s*['\"]?(\w+)['\"]?\s*(?:=|like)\s*['\"]?\1\b"),
        ("numeric_tautology", 4, r"\b(?:or|and)\s+(\d+)\s*=\s*\1\b"),
        ("time_based", 3, r"\b(?:sleep|benchmark|pg_sleep)\s*\(|\bwaitfor\s+delay\b"),
        ("information_schema", 4, r"\binformation_schema\b"),
        ("stacked_query", 4,
         r";\s*(?:select|insert|update|delete|drop|create|alter|exec|execute|shutdown"
         r"|declare)\b"),
        ("file_io", 4, r"\binto\s+(?:out|dump)file\b|\bload_file\s*\("),
        ("comment_terminator", 2, r"--(?:\s|$)|#\s*$|/\*"),
        ("hex_payload", 2, r"\b0x[0-9a-f]{6,}\b"),
        ("quote_then_keyword", 2,
         r"['\"]\s*\)?\s*(?:and|or|union|select|having|order\s+by|group\s+by)\b"),
        ("select_from", 2, r"\bselect\b.{0,100}?\bfrom\b"),
        ("concat_funcs", 2, r"\b(?:group_concat|concat_ws|char)\s*\("),
    )
)

_INLINE_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_WS = re.compile(r"\s+")


def normalize_sql_input(uri: str) -> str:
    text = unquote_plus(uri, errors="replace").lower()
    # Keep a marker so the comment signal still fires after "UNION/**/SELECT" is unwrapped.
    text = _INLINE_COMMENT.sub(" /* ", text)
    return _WS.sub(" ", text)


def sqli_score(uri: str) -> tuple[int, list[str]]:
    text = normalize_sql_input(uri)
    hits = [name for name, _, rx in SQLI_SIGNALS if rx.search(text)]
    weights = {name: weight for name, weight, _ in SQLI_SIGNALS}
    return sum(weights[h] for h in hits), hits


class SQLInjection(Detector):
    rule_id = "SENTINEL-003"
    title = "SQL Injection Attempt"
    mitre_technique = "T1190"

    def evaluate(self, event: Event) -> list[Alert]:
        if event.source != "nginx":
            return []
        uri = event.fields.get("uri") or ""
        if not uri:
            return []
        score, hits = sqli_score(uri)
        if score < self.settings.sqli_score_threshold:
            return []
        severity: Severity = "Critical" if score >= 10 else "High" if score >= 7 else "Medium"
        return [self.make_alert(event, severity, {
            "score": score,
            "threshold": self.settings.sqli_score_threshold,
            "signals": hits,
            "uri": uri[:2048],
            "status": event.fields.get("status"),
        })]


_TRAVERSAL = re.compile(r"(?:^|(?<=[/=?&;:]))\.\.(?=/|$)")
_OVERLONG = re.compile(r"%c0%a[ef]|%c1%9c|%e0%80%a[ef]|%u002e|%u2215|%u2216", re.I)
_SENSITIVE = re.compile(
    r"/etc/(?:passwd|shadow|group|hosts)\b|/proc/self/environ|\bboot\.ini\b|\bwin\.ini\b"
)
_SLASHES = re.compile(r"/{2,}")
MAX_DECODE_ROUNDS = 3


def normalize_path_input(uri_raw: str) -> str:
    text = uri_raw.replace("\\x5C", "\\").replace("\\x5c", "\\")  # nginx-escaped backslash
    for _ in range(MAX_DECODE_ROUNDS):
        nxt = unquote(text, errors="replace")
        if nxt == text:
            break
        text = nxt
    text = text.replace("\\", "/").lower()
    return _SLASHES.sub("/", text)


class PathTraversal(Detector):
    rule_id = "SENTINEL-004"
    title = "Path Traversal Attempt"
    mitre_technique = "T1190"

    def evaluate(self, event: Event) -> list[Alert]:
        if event.source != "nginx":
            return []
        raw: Optional[str] = event.fields.get("uri_raw") or event.fields.get("uri")
        if not raw:
            return []
        text = normalize_path_input(raw)
        sequences = len(_TRAVERSAL.findall(text))
        overlong = bool(_OVERLONG.search(raw))
        sensitive = _SENSITIVE.findall(text)
        if not (sequences or overlong or sensitive):
            return []
        traversal = bool(sequences or overlong)
        severity: Severity = "Critical" if traversal and sensitive else "High"
        return [self.make_alert(event, severity, {
            "traversal_sequences": sequences,
            "overlong_encoding": overlong,
            "sensitive_targets": sorted(set(sensitive)),
            "normalized_uri": text[:2048],
            "status": event.fields.get("status"),
        })]
