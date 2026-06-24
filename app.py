"""Detection Engineering SOC Dashboard — Cybersecurity UI."""

from __future__ import annotations

import queue
from collections import Counter
from datetime import timedelta
from typing import Any

import plotly.graph_objects as go
import streamlit as st

import config
from src.ai_engine import AIEngine, resolve_analysis_mode
from src.database import get_alerts, get_logs, get_rules, update_alert
from src.logging_config import get_logger
from src.pipeline import Pipeline
from src.realtime_listener import get_listener_mode, start_alert_listener
from src.ui.cyber_theme import inject_cyber_theme, panel_title, render_alert_card, render_header

logger = get_logger("dashboard")

REALTIME_QUEUE: queue.Queue[dict[str, Any]] = queue.Queue()

SEVERITY_COLORS = {
    "critical": "#ff2d55",
    "high": "#ff6b35",
    "medium": "#ffb020",
    "low": "#00ff88",
}

CYBER_CHART_COLORS = ["#00ff88", "#00e5ff", "#7c3aed", "#ff2d55", "#ffb020", "#3b82f6"]


def _on_realtime_alert(record: dict[str, Any]) -> None:
    logger.info("Realtime alert received: %s", record.get("title"))
    REALTIME_QUEUE.put(record)


def _drain_realtime_queue() -> list[dict[str, Any]]:
    new_alerts: list[dict[str, Any]] = []
    while True:
        try:
            new_alerts.append(REALTIME_QUEUE.get_nowait())
        except queue.Empty:
            break
    return new_alerts


def _init_session_state() -> None:
    if "alerts" not in st.session_state:
        try:
            st.session_state.alerts = get_alerts(limit=50)
        except Exception:
            logger.exception("Failed to load initial alerts")
            st.session_state.alerts = []
    if "last_rule" not in st.session_state:
        st.session_state.last_rule = None
    if "listener_mode" not in st.session_state:
        st.session_state.listener_mode = start_alert_listener(_on_realtime_alert)


def _merge_alerts(new_alerts: list[dict[str, Any]]) -> None:
    if not new_alerts:
        return

    existing_ids = {alert["id"] for alert in st.session_state.alerts}
    for alert in reversed(new_alerts):
        if alert["id"] not in existing_ids:
            st.session_state.alerts.insert(0, alert)
            existing_ids.add(alert["id"])


def _count_by_severity(alerts: list[dict[str, Any]], severity: str) -> int:
    return sum(1 for a in alerts if str(a.get("severity", "")).lower() == severity)


def _render_metrics(logs: list, rules: list, alerts: list) -> None:
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("TELEMETRY", len(logs), help="Toplanan log kayıtları")
    c2.metric("DETECTION RULES", len(rules), help="Üretilen KQL kuralları")
    c3.metric("ACTIVE ALERTS", len(alerts), help="Toplam alarm")
    c4.metric("CRITICAL", _count_by_severity(alerts, "critical"), help="Kritik severity")


def _build_traffic_chart(logs: list[dict[str, Any]]):
    if not logs:
        return None

    counter: Counter[str] = Counter()
    for log in logs:
        label = log.get("source") or log.get("event_type") or "unknown"
        counter[str(label)] += 1

    labels = list(counter.keys())
    values = [counter[label] for label in labels]
    colors = [CYBER_CHART_COLORS[i % len(CYBER_CHART_COLORS)] for i in range(len(labels))]

    fig = go.Figure(
        data=[
            go.Bar(
                x=labels,
                y=values,
                marker=dict(
                    color=colors,
                    line=dict(color="rgba(0,255,136,0.4)", width=1),
                ),
            )
        ]
    )
    fig.update_layout(
        title=dict(text="NETWORK TRAFFIC // LOG DISTRIBUTION", font=dict(color="#00e5ff", size=14)),
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#94a3b8", family="JetBrains Mono"),
        height=400,
        margin=dict(l=20, r=20, t=50, b=80),
        xaxis=dict(gridcolor="rgba(0,229,255,0.08)", tickangle=-30),
        yaxis=dict(gridcolor="rgba(0,229,255,0.08)", title="COUNT"),
    )
    return fig


def _log_label(log: dict[str, Any]) -> str:
    event = log.get("event_type") or "event"
    host = log.get("hostname") or "unknown-host"
    log_id = str(log.get("id", ""))[:8]
    return f"{event} @ {host} ({log_id})"


@st.fragment(run_every=timedelta(seconds=2))
def live_alerts_panel() -> None:
    mode = get_listener_mode()
    st.session_state.listener_mode = mode

    if mode == "polling":
        try:
            st.session_state.alerts = get_alerts(limit=50)
        except Exception:
            logger.exception("Polling alert refresh failed")
    else:
        incoming = _drain_realtime_queue()
        if incoming:
            _merge_alerts(incoming)

    feed_label = "◉ LIVE THREAT FEED" if mode == "websocket" else "◉ THREAT FEED (POLL 2s)"
    panel_title(feed_label)

    if not st.session_state.alerts:
        st.markdown(
            '<p style="color:#64748b;font-size:0.85rem;">No active threats. System monitoring...</p>',
            unsafe_allow_html=True,
        )
        return

    for alert in st.session_state.alerts[:15]:
        render_alert_card(alert, SEVERITY_COLORS)
        alert_id = alert.get("id")
        if not alert_id:
            continue
        cols = st.columns([3, 1])
        with cols[0]:
            new_status = st.selectbox(
                "Triage status",
                ["open", "investigating", "resolved", "false_positive"],
                index=["open", "investigating", "resolved", "false_positive"].index(
                    str(alert.get("status", "open"))
                ),
                key=f"status_{alert_id}",
                label_visibility="collapsed",
            )
        with cols[1]:
            if st.button("ACK", key=f"save_{alert_id}", use_container_width=True):
                try:
                    update_alert(alert_id, {"status": new_status})
                    alert["status"] = new_status
                    st.toast(f"Alert triaged: {new_status}")
                except Exception:
                    logger.exception("Failed to update alert %s", alert_id)
                    st.error("Update failed.")


def _sidebar_controls() -> None:
    st.markdown("### ⚙ COMMAND")
    st.markdown(
        '<p style="color:#64748b;font-size:0.75rem;">Pipeline & detection controls</p>',
        unsafe_allow_html=True,
    )

    if st.button("▶ RUN ANALYSIS PIPELINE", use_container_width=True, type="primary"):
        with st.spinner("Scanning telemetry..."):
            try:
                result = Pipeline().analyze_unprocessed(limit=50)
                st.success(f"+{result.rules_created} rules · +{result.alerts_created} alerts")
                st.session_state.alerts = get_alerts(limit=50)
            except Exception:
                logger.exception("Pipeline analyze failed")
                st.error("Pipeline failed.")

    st.markdown("---")
    panel_title("DETECTION RULES")

    try:
        rules = get_rules(limit=8)
    except Exception:
        logger.exception("Failed to load rules")
        st.error("Rules unavailable.")
        return

    if not rules:
        st.caption("No rules deployed.")
        return

    for rule in rules:
        sev = rule.get("severity", "—")
        color = SEVERITY_COLORS.get(str(sev).lower(), "#64748b")
        with st.expander(f"▸ {rule.get('name', 'Rule')}"):
            st.markdown(
                f'<span style="color:{color};font-size:0.75rem;font-weight:700;">{sev.upper()}</span>',
                unsafe_allow_html=True,
            )
            st.caption(rule.get("standard", "—"))
            st.code(rule.get("content", ""), language="sql")


def main() -> None:
    st.set_page_config(
        page_title="LOGTUT SOC",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    inject_cyber_theme()
    _init_session_state()
    _merge_alerts(_drain_realtime_queue())

    analysis_mode = resolve_analysis_mode()
    render_header(analysis_mode)

    try:
        logs = get_logs(limit=200)
        rules = get_rules(limit=100)
        alerts = st.session_state.alerts
    except Exception:
        logger.exception("Failed to load dashboard data")
        logs, rules, alerts = [], [], []

    _render_metrics(logs, rules, alerts)

    with st.sidebar:
        _sidebar_controls()

    col_feed, col_chart = st.columns([1, 1.15])

    with col_feed:
        st.markdown('<div class="cyber-panel">', unsafe_allow_html=True)
        live_alerts_panel()
        st.markdown("</div>", unsafe_allow_html=True)

    with col_chart:
        st.markdown('<div class="cyber-panel">', unsafe_allow_html=True)
        chart = _build_traffic_chart(logs)
        if chart:
            st.plotly_chart(chart, use_container_width=True)
        else:
            st.caption("Awaiting telemetry data...")
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("---")
    panel_title("◈ KQL RULE GENERATOR")

    if not logs:
        st.warning("No logs available. Run `python lab/poc_lab_simulator.py --full`")
        return

    col_sel, col_action = st.columns([2, 1])
    with col_sel:
        log_options = {_log_label(log): log for log in logs}
        selected_label = st.selectbox("Target log event", list(log_options.keys()))
        selected_log = log_options[selected_label]

    with col_action:
        st.markdown("<br>", unsafe_allow_html=True)
        generate = st.button("⚡ GENERATE KQL", type="primary", use_container_width=True)

    mode_text = "Cursor LLM" if analysis_mode == "cursor" else "Heuristic fallback"
    st.caption(f"Analysis engine: **{mode_text}**")

    if generate:
        with st.spinner("Threat analysis in progress..."):
            try:
                result = AIEngine().analyze_and_save(selected_log, selected_log.get("id"))
            except Exception as exc:
                logger.exception("KQL rule generation failed")
                st.error(f"Analysis failed: {exc}")
                return

        if result is None:
            st.warning("No threat detected.")
            return

        rule = result.get("rule", result)
        alert = result.get("alert")
        st.session_state.last_rule = rule
        st.session_state.alerts = get_alerts(limit=50)
        st.success(f"Rule deployed: **{rule['name']}**")
        if alert:
            st.info(f"Alert fired: **{alert['title']}**")

    if st.session_state.last_rule:
        rule = st.session_state.last_rule
        if isinstance(rule, dict) and "rule" in rule:
            rule = rule["rule"]

        st.markdown('<div class="cyber-terminal">', unsafe_allow_html=True)
        st.markdown("##### ▸ LATEST DETECTION OUTPUT")
        m1, m2 = st.columns(2)
        m1.markdown(f"**Standard:** `{rule.get('standard', '—')}`")
        m2.markdown(f"**Severity:** `{rule.get('severity', '—')}`")
        st.code(rule.get("content", ""), language="sql")
        st.markdown("</div>", unsafe_allow_html=True)


if __name__ == "__main__":
    main()
