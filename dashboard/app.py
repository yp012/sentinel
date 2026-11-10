"""SentinelSOAR SOC dashboard (Streamlit).

Run with ``streamlit run dashboard/app.py``. Polls the engine API at ``ENGINE_URL``
(default http://localhost:8000) every 2 s over HTTP; it never imports ``sentinel``.
All data access and formatting lives in ``dashboard/data.py``.

The API key typed in the sidebar is kept in Streamlit session state only (per browser
session, in memory). It is sent as the ``X-API-Key`` header and never logged or
written to disk.
"""

from __future__ import annotations

import logging
from typing import Any, Mapping, Optional, Sequence

import pandas as pd
import plotly.express as px
import streamlit as st
from streamlit.errors import StreamlitAPIException

try:
    from dashboard import data as d
except ImportError:  # `streamlit run dashboard/app.py` puts dashboard/ on sys.path
    import data as d  # type: ignore[no-redef]

logger = logging.getLogger(__name__)

REFRESH_S = 2
HAS_FRAGMENT = hasattr(st, "fragment")  # Streamlit >= 1.37
INCIDENT_LIMIT = 500
SEVERITY_ICONS = {"Critical": "🟣", "High": "🟠", "Medium": "🔷", "Low": "🟢"}

CSS = """
<style>
:root { --soc-bg: #0b0f17; --soc-panel: #121826; --soc-line: #1f2a3d;
        --soc-ink: #d7dde8; --soc-dim: #8a96ab; --soc-accent: #3987e5; }
.stApp { background: var(--soc-bg); color: var(--soc-ink); }
[data-testid="stSidebar"] { background: #0e1420; border-right: 1px solid var(--soc-line); }
[data-testid="stMetric"] { background: var(--soc-panel); border: 1px solid var(--soc-line);
        border-radius: 8px; padding: 10px 14px; }
[data-testid="stMetricLabel"] p { color: var(--soc-dim); text-transform: uppercase;
        letter-spacing: .06em; font-size: .72rem; }
[data-testid="stMetricValue"] { font-family: ui-monospace, Menlo, monospace; }
h1, h2, h3 { letter-spacing: .02em; }
.soc-queue { width: 100%; border-collapse: collapse; font-size: .85rem; }
.soc-queue th { text-align: left; color: var(--soc-dim); font-weight: 500;
        border-bottom: 1px solid var(--soc-line); padding: 6px 8px; }
.soc-queue td { padding: 6px 8px; border-bottom: 1px solid var(--soc-line);
        vertical-align: top; }
.soc-rule { font-family: ui-monospace, Menlo, monospace; font-weight: 600; }
.soc-title { color: var(--soc-dim); font-size: .78rem; }
.soc-mono { font-family: ui-monospace, Menlo, monospace; }
.soc-dim { color: var(--soc-dim); font-size: .78rem; }
.soc-mitre { display: inline-block; padding: 1px 7px; border-radius: 4px;
        background: #1b2a44; color: #9ec5f4 !important; text-decoration: none;
        font-family: ui-monospace, Menlo, monospace; font-size: .78rem;
        border: 1px solid #2a4370; }
.soc-status { padding: 1px 7px; border-radius: 10px; font-size: .75rem;
        border: 1px solid var(--soc-line); }
.soc-status-open { color: #f0a0c0; border-color: #6b2a48; }
.soc-status-contained { color: #9ec5f4; border-color: #2a4370; }
.soc-status-resolved, .soc-status-false_positive { color: var(--soc-dim); }
.soc-empty { color: var(--soc-dim); padding: 12px 4px; }
.soc-banner { color: var(--soc-dim); font-size: .8rem; }
</style>
"""

PLOT_LAYOUT = dict(
    template="plotly_dark", height=280, margin=dict(l=8, r=8, t=36, b=8),
    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
    font=dict(color="#d7dde8", size=12), bargap=0.25,
    xaxis=dict(gridcolor="#1f2a3d", zeroline=False),
    yaxis=dict(gridcolor="#1f2a3d", zeroline=False),
    legend=dict(orientation="h", y=1.12, x=0, title=None),
)
PLOT_CONFIG = {"displayModeBar": False}


# ------------------------------------------------------------------ helpers

def _client() -> d.EngineClient:
    return d.EngineClient(d.engine_url_from_env(), st.session_state.get("api_key", ""))


def _flash(level: str, message: str) -> None:
    """Keep an action result on screen across the 2 s refreshes until dismissed."""
    st.session_state["flash"] = (level, message)


def _show_flash() -> None:
    flash = st.session_state.get("flash")
    if not flash:
        return
    level, message = flash
    cols = st.columns([12, 1])
    getattr(cols[0], level if level in ("success", "warning", "info", "error") else "info")(
        message)
    if cols[1].button("Dismiss", key="flash_dismiss"):
        st.session_state.pop("flash", None)
        _rerun()


def _rerun() -> None:
    """Redraw now so an action's result shows without waiting for the next tick."""
    if HAS_FRAGMENT:
        try:
            st.rerun(scope="fragment")
        except StreamlitAPIException:  # fragment ran as part of a full-page run
            pass
    st.rerun()


def _empty(message: str) -> None:
    st.markdown(f'<div class="soc-empty">{message}</div>', unsafe_allow_html=True)


def _chart(fig: Any, key: str) -> None:
    fig.update_layout(**PLOT_LAYOUT)
    st.plotly_chart(fig, key=key, theme=None, config=PLOT_CONFIG)


# ---------------------------------------------------------------- sections

def render_kpis(metrics: Mapping[str, Any]) -> None:
    for col, (label, value) in zip(st.columns(6), d.kpis(metrics)):
        col.metric(label, value)
    fw = metrics.get("firewall") or {}
    st.markdown(
        f'<div class="soc-banner">intel: {metrics.get("intel_mode", "?")} · firewall: '
        f'{"REAL iptables" if fw.get("real") else "simulated"} · tailing: '
        f'{"yes" if metrics.get("tailing") else "no"} · alerts: '
        f'{d.fmt_int(metrics.get("alerts_total"))} · uptime: '
        f'{d.fmt_int(metrics.get("uptime_s"))} s</div>', unsafe_allow_html=True)


def render_queues(incidents: Sequence[Mapping[str, Any]]) -> None:
    st.subheader("Triage queues")
    queues = d.triage_queues(incidents)
    labels = [f"{SEVERITY_ICONS[s]} {s} ({len(queues[s])})" for s in d.SEVERITY_ORDER]
    for tab, sev in zip(st.tabs(labels), d.SEVERITY_ORDER):
        with tab:
            st.markdown(d.queue_html(queues[sev], sev), unsafe_allow_html=True)


def render_charts(metrics: Mapping[str, Any], incidents: Sequence[Mapping[str, Any]]) -> None:
    st.subheader("Activity")
    left, right = st.columns(2)
    with left:
        rows = d.alerts_over_time(incidents)
        if rows:
            fig = px.bar(pd.DataFrame(rows), x="time", y="alerts", color="severity",
                         color_discrete_map=d.SEVERITY_COLORS,
                         category_orders={"severity": list(d.SEVERITY_ORDER)},
                         title="Alerts over time by severity (per minute)")
            fig.update_traces(marker_line_width=1, marker_line_color="#0b0f17")
            _chart(fig, "chart_alerts")
        else:
            _empty("No alerts yet.")
    with right:
        rows = d.technique_distribution(metrics)
        if rows:
            fig = px.bar(pd.DataFrame(rows), x="alerts", y="technique", orientation="h",
                         title="MITRE ATT&CK technique distribution")
            fig.update_traces(marker_color="#3987e5")
            fig.update_yaxes(autorange="reversed", title=None)
            _chart(fig, "chart_mitre")
        else:
            _empty("No techniques observed yet.")
    left, right = st.columns(2)
    with left:
        rows = d.top_attackers(incidents)
        if rows:
            fig = px.bar(pd.DataFrame(rows), x="alerts", y="src_ip", orientation="h",
                         title="Top attacker IPs (alerts)")
            fig.update_traces(marker_color="#3987e5")
            fig.update_yaxes(autorange="reversed", title=None, type="category")
            _chart(fig, "chart_ips")
        else:
            _empty("No attacker IPs yet.")
    with right:
        rows = d.eps_series(metrics)
        if rows:
            fig = px.area(pd.DataFrame(rows), x="time", y="eps", title="Events / sec")
            fig.update_traces(line_color="#3987e5", line_width=2)
            fig.update_layout(hovermode="x unified")
            _chart(fig, "chart_eps")
        else:
            _empty("No events yet.")


def _incident_label(incidents_by_id: Mapping[str, Mapping[str, Any]], inc_id: str) -> str:
    inc = incidents_by_id.get(inc_id) or {}
    return (f"{inc.get('severity', '?')} · {inc.get('rule_id', '?')} · "
            f"{inc.get('src_ip') or inc.get('user') or '-'} · {inc.get('status', '?')} · "
            f"{inc_id}")


def render_incident(client: d.EngineClient, incidents: Sequence[Mapping[str, Any]]) -> None:
    st.subheader("Incident detail")
    if not incidents:
        _empty("No incidents yet.")
        return
    ordered = d.sort_incidents(incidents)
    by_id = {i["id"]: i for i in ordered if i.get("id")}
    chosen = st.selectbox("Incident", list(by_id), key="selected_incident",
                          format_func=lambda i: _incident_label(by_id, i))
    inc: Optional[Mapping[str, Any]] = by_id.get(chosen) if chosen else None
    if inc is None:
        return

    info, actions = st.columns([3, 2])
    with info:
        st.markdown(f"**{inc.get('title', '')}**")
        st.markdown(
            f"{SEVERITY_ICONS.get(inc.get('severity'), '')} {inc.get('severity')} · "
            f"`{inc.get('mitre_technique', '')}` · status **{inc.get('status')}** · "
            f"priority {inc.get('priority') or 'n/a'} · alerts {inc.get('alert_count', 0)} · "
            f"MTTD {d.fmt_ms(inc.get('mttd_ms'))} · MTTR {d.fmt_ms(inc.get('mttr_ms'))}")
        if inc.get("tags"):
            st.caption("tags: " + ", ".join(map(str, inc["tags"])))
    with actions:
        ip = inc.get("src_ip") or ""
        b1, b2, b3 = st.columns(3)
        if b1.button("Contain", key=f"contain_{chosen}", type="primary",
                     help="Block the source IP and revoke sessions (safety guard applies)"):
            _flash(*d.describe_contain(client.contain(chosen, note="dashboard one-click")))
            _rerun()
        if b2.button("Unblock IP", key=f"unblock_{chosen}", disabled=not ip):
            _flash(*_describe_unblock(client.unblock(ip), ip))
            _rerun()
        if b3.button("Mark false positive", key=f"fp_{chosen}",
                     disabled=inc.get("status") == "false_positive"):
            res = client.set_status(chosen, "false_positive", note="marked from dashboard")
            _flash("success" if res.ok else "error",
                   f"{chosen} marked false positive." if res.ok
                   else f"Could not update {chosen}: {res.error}")
            _rerun()

    evidence_col, intel_col = st.columns(2)
    with evidence_col:
        st.markdown("**Evidence**")
        st.json((inc.get("alert") or {}).get("evidence") or {}, expanded=False)
    with intel_col:
        st.markdown("**Threat intel (AbuseIPDB)**")
        if inc.get("intel"):
            st.json(inc["intel"], expanded=False)
        else:
            _empty("No intel for this incident.")

    st.markdown("**SOAR action timeline**")
    rows = d.action_timeline(inc)
    if rows:
        st.dataframe(pd.DataFrame(rows), hide_index=True, key=f"actions_{chosen}",
                     column_config={"duration_ms": st.column_config.NumberColumn(
                         "duration (ms)", format="%.3f")})
    else:
        _empty("No actions recorded.")


def _describe_unblock(result: d.ApiResult, ip: str) -> tuple[str, str]:
    if result.ok:
        return "success", f"Unblocked {ip}."
    if result.status == 404:
        return "info", f"No active firewall rule for {ip}."
    return "error", f"Unblock of {ip} failed: {result.error}"


def render_firewall(client: d.EngineClient, rules_result: d.ApiResult,
                    incidents: Sequence[Mapping[str, Any]]) -> None:
    left, right = st.columns(2)
    with left:
        st.subheader("Active firewall rules")
        if not rules_result.ok:
            st.warning(f"Firewall rules unavailable: {rules_result.error}")
        else:
            rows = d.firewall_table(rules_result.data)
            mode = "REAL iptables" if (rules_result.data or {}).get("real") else "simulated"
            st.caption(f"{len(rows)} rule(s) · {mode}")
            if rows:
                st.dataframe(pd.DataFrame(rows), hide_index=True, key="fw_rules")
                pick, go = st.columns([3, 1])
                ip = pick.selectbox("Rule", [r["ip"] for r in rows], key="fw_pick",
                                    label_visibility="collapsed")
                if go.button("Unblock", key="fw_unblock") and ip:
                    _flash(*_describe_unblock(client.unblock(ip), ip))
                    _rerun()
            else:
                _empty("No active rules.")
    with right:
        st.subheader("Containment audit log")
        rows = d.audit_log(incidents)
        if rows:
            st.dataframe(pd.DataFrame(rows), hide_index=True, key="audit_log")
        else:
            _empty("No analyst actions yet.")


def render_unreachable(client: d.EngineClient, error: str) -> None:
    st.error(f"Engine unavailable: {error}.")
    st.markdown(
        f"The dashboard polls `{client.base_url}` every {REFRESH_S} s and will recover "
        "on its own once the engine is up. Start it with "
        "`uvicorn sentinel.api:app --port 8000`, or set `ENGINE_URL`.")


def render() -> None:
    client = _client()
    health = client.health()
    if not health.ok:
        render_unreachable(client, health.error)
        return
    metrics = client.metrics()
    if metrics.unauthorized:
        st.warning("The engine rejected the API key (missing or invalid). "
                   "Enter it in the sidebar.")
        return
    if not metrics.ok:
        render_unreachable(client, metrics.error)
        return
    inc_result = client.incidents(limit=INCIDENT_LIMIT)
    incidents = inc_result.data.get("incidents", []) if inc_result.ok else []
    if not inc_result.ok:
        st.warning(f"Incidents unavailable: {inc_result.error}")

    render_kpis(metrics.data)
    _show_flash()
    render_queues(incidents)
    render_charts(metrics.data, incidents)
    render_incident(client, incidents)
    render_firewall(client, client.firewall_rules(), incidents)


def live() -> None:
    try:
        render()
    except Exception as exc:  # last-resort guard: never show a stack trace in the UI
        logger.exception("dashboard render failed: %s", type(exc).__name__)
        st.error("The dashboard hit an unexpected error; retrying on the next refresh.")


def sidebar() -> None:
    with st.sidebar:
        st.markdown("## 🛡️ SentinelSOAR")
        st.caption(f"Engine: `{d.engine_url_from_env()}`")
        st.text_input("API key", type="password", key="api_key",
                      help="Sent as X-API-Key. Kept in this browser session only.")
        st.caption(f"Auto-refresh every {REFRESH_S} s.")


def main() -> None:
    st.set_page_config(page_title="SentinelSOAR SOC", page_icon="🛡️", layout="wide",
                       initial_sidebar_state="expanded")
    st.markdown(CSS, unsafe_allow_html=True)
    sidebar()
    st.title("SentinelSOAR · Security Operations")
    if HAS_FRAGMENT:
        st.fragment(live, run_every=REFRESH_S)()
    else:  # Streamlit < 1.37: no fragments, refresh on demand
        live()
        st.button("Refresh", key="manual_refresh")


main()
