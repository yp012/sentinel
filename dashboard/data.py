"""Data access and formatting for the SOC dashboard, kept free of Streamlit so it can
be unit tested on its own.

The dashboard talks to the engine over HTTP only (``requests``); it must not import
the ``sentinel`` package, so the dashboard image stays small. Endpoint paths, the
``X-API-Key`` header and the response shapes mirror ``sentinel/api.py`` and
``sentinel/store.py``.

Every ``EngineClient`` call returns an ``ApiResult`` and never raises, so the UI can
show an "engine unreachable" or "bad API key" state instead of a stack trace. The API
key is only ever placed in the request header; it is never logged or stored here.
"""

from __future__ import annotations

import html
import ipaddress
import os
import re
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping, Optional, Sequence
from urllib.parse import quote

import requests

DEFAULT_ENGINE_URL = "http://localhost:8000"
API_KEY_HEADER = "X-API-Key"
INCIDENT_ID_RE = re.compile(r"^INC-[0-9a-f]{12}$")
DEFAULT_TIMEOUT_S = 3.0

# Triage order: most severe first.
SEVERITY_ORDER: tuple[str, ...] = ("Critical", "High", "Medium", "Low")
# Validated for the dark surface (adjacent-pair CVD and contrast checks). Severity is
# never shown by color alone: queues, legends and badges always carry the label.
SEVERITY_COLORS = {
    "Critical": "#d55181",
    "High": "#c98500",
    "Medium": "#9085e9",
    "Low": "#199e70",
}
STATUSES: tuple[str, ...] = ("open", "contained", "resolved", "false_positive")
NA = "n/a"
EPS_WINDOW_BUCKETS = 10   # complete buckets averaged for the events/sec KPI


def engine_url_from_env() -> str:
    return (os.getenv("ENGINE_URL", "").strip() or DEFAULT_ENGINE_URL).rstrip("/")


def auth_headers(api_key: Optional[str]) -> dict[str, str]:
    """The auth header, or nothing when no key is set (an engine without
    ``SENTINEL_API_KEY`` needs none)."""
    key = (api_key or "").strip()
    return {API_KEY_HEADER: key} if key else {}


# ------------------------------------------------------------------- client

@dataclass(frozen=True)
class ApiResult:
    ok: bool
    status: Optional[int] = None    # HTTP status; None when the engine was not reached
    data: Any = None
    error: str = ""

    @property
    def unreachable(self) -> bool:
        return not self.ok and self.status is None

    @property
    def unauthorized(self) -> bool:
        return self.status == 401


class EngineClient:
    def __init__(self, base_url: str, api_key: Optional[str] = None, *,
                 timeout: float = DEFAULT_TIMEOUT_S) -> None:
        self.base_url = base_url.rstrip("/")
        self._headers = auth_headers(api_key)
        self.timeout = timeout

    def __repr__(self) -> str:  # never show the key
        return f"EngineClient({self.base_url!r})"

    def _request(self, method: str, path: str, *, json: Any = None,
                 params: Optional[Mapping[str, Any]] = None) -> ApiResult:
        url = f"{self.base_url}{path}"
        try:
            resp = requests.request(method, url, headers=dict(self._headers), json=json,
                                    params=params, timeout=self.timeout)
        except requests.Timeout:
            return ApiResult(False, error=f"engine at {self.base_url} timed out")
        except requests.RequestException:
            return ApiResult(False, error=f"engine unreachable at {self.base_url}")
        try:
            body = resp.json()
        except ValueError:
            body = None
        if resp.status_code == 401:
            return ApiResult(False, 401, body, "invalid or missing API key")
        if not 200 <= resp.status_code < 300:
            return ApiResult(False, resp.status_code, body,
                             f"HTTP {resp.status_code}: {_detail(body)}")
        if body is None:
            return ApiResult(False, resp.status_code, None, "engine returned a non-JSON body")
        return ApiResult(True, resp.status_code, body)

    def health(self) -> ApiResult:
        return self._request("GET", "/health")

    def metrics(self) -> ApiResult:
        return self._request("GET", "/api/metrics")

    def incidents(self, limit: int = 500) -> ApiResult:
        return self._request("GET", "/api/incidents",
                             params={"limit": max(1, min(int(limit), 1000))})

    def incident(self, incident_id: str) -> ApiResult:
        bad = _check_incident_id(incident_id)
        return bad or self._request("GET", f"/api/incidents/{incident_id}")

    def contain(self, incident_id: str, note: str = "") -> ApiResult:
        bad = _check_incident_id(incident_id)
        return bad or self._request("POST", f"/api/incidents/{incident_id}/contain",
                                    json={"note": note})

    def set_status(self, incident_id: str, status: str, note: str = "") -> ApiResult:
        bad = _check_incident_id(incident_id)
        if bad:
            return bad
        if status not in STATUSES:
            return ApiResult(False, error=f"unknown status {status!r}")
        return self._request("POST", f"/api/incidents/{incident_id}/status",
                             json={"status": status, "note": note})

    def firewall_rules(self) -> ApiResult:
        return self._request("GET", "/api/firewall/rules")

    def unblock(self, ip: str) -> ApiResult:
        try:
            addr = str(ipaddress.ip_address(ip.strip()))
        except (ValueError, AttributeError):
            return ApiResult(False, error=f"not a valid IP address: {ip!r}")
        return self._request("DELETE", f"/api/firewall/rules/{quote(addr, safe='')}")


def _check_incident_id(incident_id: str) -> Optional[ApiResult]:
    if not isinstance(incident_id, str) or not INCIDENT_ID_RE.match(incident_id):
        return ApiResult(False, error=f"not a valid incident id: {incident_id!r}")
    return None


def _detail(body: Any) -> str:
    if isinstance(body, dict) and "detail" in body:
        detail = body["detail"]
        if isinstance(detail, list):  # FastAPI validation errors
            return "; ".join(str(d.get("msg", d)) if isinstance(d, dict) else str(d)
                             for d in detail)
        return str(detail)
    return "request failed"


# --------------------------------------------------------------- formatting

def _num(value: Any) -> Optional[float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def fmt_int(value: Any) -> str:
    n = _num(value)
    return NA if n is None else f"{int(n):,}"


def fmt_ms(value: Any) -> str:
    n = _num(value)
    if n is None:
        return NA
    return f"{n:,.0f} ms" if n >= 100 else f"{n:,.2f} ms"


def fmt_rate(value: Any) -> str:
    n = _num(value)
    return NA if n is None else f"{n:,.1f}/s"


def events_per_sec(metrics: Mapping[str, Any],
                   window: int = EPS_WINDOW_BUCKETS) -> Optional[float]:
    """Mean rate over the last ``window`` complete buckets. The newest bucket is still
    filling, so it is left out. None when nothing has been ingested yet."""
    if not metrics.get("events_ingested"):
        return None
    series = metrics.get("events_per_sec") or {}
    points = series.get("points") or []
    bucket_s = _num(series.get("bucket_s")) or 1.0
    complete = points[:-1][-window:] if len(points) > 1 else points
    if not complete:
        return None
    total = sum(_num(p.get("count")) or 0 for p in complete)
    return total / (len(complete) * bucket_s)


def _aggregate_mean(metrics: Mapping[str, Any], name: str) -> Optional[float]:
    agg = metrics.get(name) or {}
    if not agg.get("count"):
        return None
    return _num(agg.get("mean_ms"))


def kpis(metrics: Optional[Mapping[str, Any]]) -> list[tuple[str, str]]:
    """The six top-row KPIs as (label, display value); "n/a" when there are no samples."""
    m = metrics or {}
    firewall = m.get("firewall") or {}
    by_status = m.get("incidents_by_status") or {}
    return [
        ("Events ingested", fmt_int(m.get("events_ingested"))),
        ("Events / sec", fmt_rate(events_per_sec(m))),
        ("Open incidents", fmt_int(by_status.get("open"))),
        ("Blocked IPs", fmt_int(firewall.get("active_rules"))),
        ("Mean MTTD", fmt_ms(_aggregate_mean(m, "mttd"))),
        ("Mean MTTR", fmt_ms(_aggregate_mean(m, "mttr"))),
    ]


def severity_rank(severity: Any) -> int:
    """0 for Critical ... 3 for Low; anything unknown sorts last."""
    try:
        return SEVERITY_ORDER.index(severity)
    except ValueError:
        return len(SEVERITY_ORDER)


def sort_incidents(incidents: Iterable[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    """Most severe first, then newest (by last update) first."""
    return sorted(incidents, key=lambda i: (severity_rank(i.get("severity")),
                                            -(_num(i.get("updated_at")) or 0.0)))


def intel_score(incident: Mapping[str, Any]) -> Optional[int]:
    intel = incident.get("intel")
    if isinstance(intel, dict):
        score = _num(intel.get("score"))
        return int(score) if score is not None else None
    return None


def queue_row(incident: Mapping[str, Any]) -> dict[str, Any]:
    score = intel_score(incident)
    return {
        "id": incident.get("id", ""),
        "rule": incident.get("rule_id", ""),
        "title": incident.get("title", ""),
        "mitre": incident.get("mitre_technique", ""),
        "src_ip": incident.get("src_ip") or "-",
        "user": incident.get("user") or "-",
        "abuse_score": NA if score is None else str(score),
        "status": incident.get("status", ""),
        "alerts": incident.get("alert_count", len(incident.get("alert_ids") or [])),
        "updated": incident.get("updated_at_iso") or "",
    }


def triage_queues(incidents: Iterable[Mapping[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Incidents bucketed by severity (Critical first), each queue newest first."""
    queues: dict[str, list[Mapping[str, Any]]] = {sev: [] for sev in SEVERITY_ORDER}
    for inc in incidents:
        sev = inc.get("severity")
        if sev in queues:
            queues[sev].append(inc)
    return {sev: [queue_row(i) for i in sorted(items, key=lambda i: -(
        _num(i.get("updated_at")) or 0.0))] for sev, items in queues.items()}


def mitre_url(technique: str) -> str:
    return f"https://attack.mitre.org/techniques/{technique.replace('.', '/')}/"


def queue_html(rows: Sequence[Mapping[str, Any]], severity: str, limit: int = 50) -> str:
    """Render one triage queue as an HTML table. Every value comes from log-derived
    data, so all of it is escaped."""
    if not rows:
        return '<div class="soc-empty">No incidents in this queue.</div>'
    color = SEVERITY_COLORS.get(severity, "#888888")
    e = html.escape
    body = []
    for r in rows[:limit]:
        mitre = str(r.get("mitre", ""))
        status = str(r.get("status", ""))
        body.append(
            f'<tr style="border-left:4px solid {color}">'
            f'<td><span class="soc-rule">{e(str(r.get("rule", "")))}</span>'
            f'<div class="soc-title">{e(str(r.get("title", "")))}</div></td>'
            f'<td><a class="soc-mitre" href="{e(mitre_url(mitre))}" target="_blank" '
            f'rel="noopener noreferrer">{e(mitre)}</a></td>'
            f'<td class="soc-mono">{e(str(r.get("src_ip", "")))}</td>'
            f'<td class="soc-mono">{e(str(r.get("abuse_score", NA)))}</td>'
            f'<td><span class="soc-status soc-status-{e(status)}">{e(status)}</span></td>'
            f'<td class="soc-mono soc-dim">{e(str(r.get("id", "")))}</td>'
            "</tr>")
    more = (f'<div class="soc-dim">Showing {limit} of {len(rows)}.</div>'
            if len(rows) > limit else "")
    return ('<table class="soc-queue"><thead><tr><th>Rule</th><th>MITRE</th>'
            "<th>Source IP</th><th>AbuseIPDB</th><th>Status</th><th>Incident</th>"
            f'</tr></thead><tbody>{"".join(body)}</tbody></table>{more}')


# ------------------------------------------------------------ chart series

def _parse_iso(value: Any) -> Optional[datetime]:
    if not isinstance(value, str):
        return None
    try:
        ts = datetime.fromisoformat(value)
    except ValueError:
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def alerts_over_time(incidents: Iterable[Mapping[str, Any]],
                     bucket_s: int = 60) -> list[dict[str, Any]]:
    """Alert counts per (time bucket, severity), from incident timelines."""
    counts: Counter = Counter()
    for inc in incidents:
        for entry in inc.get("timeline") or []:
            if entry.get("kind") != "alert":
                continue
            ts = _parse_iso(entry.get("at"))
            if ts is None:
                continue
            epoch = int(ts.timestamp()) // bucket_s * bucket_s
            counts[(epoch, entry.get("severity", "Low"))] += 1
    return [{"time": datetime.fromtimestamp(epoch, tz=timezone.utc), "severity": sev,
             "alerts": n}
            for (epoch, sev), n in sorted(counts.items(),
                                          key=lambda kv: (kv[0][0], severity_rank(kv[0][1])))]


def technique_distribution(metrics: Mapping[str, Any]) -> list[dict[str, Any]]:
    by_tech = metrics.get("alerts_by_technique") or {}
    return [{"technique": t, "alerts": n}
            for t, n in sorted(by_tech.items(), key=lambda kv: (-kv[1], kv[0]))]


def top_attackers(incidents: Iterable[Mapping[str, Any]], n: int = 10) -> list[dict[str, Any]]:
    counts: Counter = Counter()
    for inc in incidents:
        ip = inc.get("src_ip")
        if ip:
            counts[ip] += int(inc.get("alert_count") or len(inc.get("alert_ids") or []) or 1)
    return [{"src_ip": ip, "alerts": c}
            for ip, c in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:n]]


def eps_series(metrics: Mapping[str, Any]) -> list[dict[str, Any]]:
    points = (metrics.get("events_per_sec") or {}).get("points") or []
    out = []
    for p in points[:-1] if len(points) > 1 else points:   # drop the filling bucket
        ts = _parse_iso(p.get("t"))
        if ts is not None:
            out.append({"time": ts, "eps": _num(p.get("eps")) or 0.0})
    return out


# ------------------------------------------------------- incident detail

def action_timeline(incident: Mapping[str, Any]) -> list[dict[str, Any]]:
    """SOAR and analyst actions on one incident, in the order they ran."""
    rows = []
    for a in incident.get("actions") or []:
        rows.append({
            "at": a.get("at") or "",
            "actor": a.get("actor", ""),
            "action": a.get("name", ""),
            "status": a.get("status", ""),
            "duration_ms": _num(a.get("duration_ms")),
            "detail": a.get("detail", ""),
        })
    return rows


def audit_log(incidents: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Analyst containment / triage activity across incidents, newest first."""
    rows = []
    for inc in incidents:
        for entry in inc.get("timeline") or []:
            if entry.get("actor") != "analyst":
                continue
            kind = entry.get("kind")
            if kind == "action":
                what, outcome = entry.get("name", ""), entry.get("status", "")
                detail = entry.get("detail", "")
            elif kind == "status":
                what = "status change"
                outcome = f"{entry.get('from', '')} -> {entry.get('to', '')}"
                detail = entry.get("note", "")
            elif kind == "note":
                what, outcome, detail = "note", "", entry.get("note", "")
            else:
                continue
            rows.append({"at": entry.get("at") or "", "incident": inc.get("id", ""),
                         "src_ip": inc.get("src_ip") or "-", "action": what,
                         "outcome": outcome, "detail": detail})
    rows.sort(key=lambda r: r["at"], reverse=True)
    return rows


def firewall_table(payload: Optional[Mapping[str, Any]]) -> list[dict[str, Any]]:
    rules = (payload or {}).get("rules") or []
    return [{"ip": r.get("ip", ""), "command": r.get("command", ""),
             "reason": r.get("reason", ""), "created": r.get("created_at_iso") or "",
             "expires": r.get("expires_at_iso") or "never"} for r in rules]


def describe_contain(result: ApiResult) -> tuple[str, str]:
    """(level, message) for a /contain response; level is success|warning|info|error."""
    if not result.ok:
        return "error", f"Containment failed: {result.error}"
    data = result.data if isinstance(result.data, dict) else {}
    block = data.get("block") or {}
    status = block.get("status", "")
    ip = (data.get("incident") or {}).get("src_ip") or "the source IP"
    sessions = data.get("sessions") or {}
    tail = f" Sessions: {sessions.get('detail')}." if sessions.get("detail") else ""
    if data.get("blocked"):
        if status == "skipped_already_blocked":
            return "info", f"{ip} was already blocked.{tail}"
        return "success", f"Blocked {ip}: {block.get('detail', '')}.{tail}"
    if status == "refused_safety_guard":
        return "warning", f"Safety guard refused to block {ip}: {block.get('detail', '')}.{tail}"
    if status == "skipped_no_ip":
        return "warning", f"Nothing to block: incident has no source IP.{tail}"
    return "error", f"Block of {ip} failed ({status or 'unknown'}): {block.get('detail', '')}"
