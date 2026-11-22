"""Paylaşılan dashboard yardımcıları — SOC ve Lab sayfaları."""

from __future__ import annotations

import queue
from collections import Counter
from datetime import timedelta
from typing import Any

import plotly.graph_objects as go
import streamlit as st

from src.ai_engine import resolve_analysis_mode
from src.database import get_alerts, get_rules, update_alert
from src.logging_config import get_logger
from src.realtime_listener import get_listener_mode, start_alert_listener
from src.ui.cyber_theme import panel_title, render_alert_card
from src.ui.rule_explainer import (
    explain_standard,
    get_rule_action_hint,
    get_rule_summary,
)

logger = get_logger("dashboard")

REALTIME_QUEUE: queue.Queue[dict[str, Any]] = queue.Queue()

SEVERITY_COLORS = {
    "critical": "#ff2d55",
    "high": "#ff6b35",
    "medium": "#ffb020",
    "low": "#00ff88",
}

SEVERITY_TR = {
    "critical": "Kritik",
    "high": "Yüksek",
    "medium": "Orta",
    "low": "Düşük",
}

STATUS_TR = {
    "open": "Açık",
    "investigating": "İnceleniyor",
    "resolved": "Çözüldü",
    "false_positive": "Yanlış alarm",
}

STATUS_OPTIONS = list(STATUS_TR.keys())
ARCHIVED_STATUSES = frozenset({"resolved", "false_positive"})
CYBER_CHART_COLORS = ["#00ff88", "#00e5ff", "#7c3aed", "#ff2d55", "#ffb020", "#3b82f6"]

EVENT_TYPE_TR = {
    "powershell_execution": "PowerShell çalıştırma",
    "lateral_movement": "Yanal hareket",
    "credential_access": "Kimlik bilgisi erişimi",
    "suspicious_execution": "Şüpheli çalıştırma",
    "data_exfiltration": "Veri sızdırma",
    "malware_download": "Zararlı indirme",
    "privilege_escalation": "Yetki yükseltme",
    "persistence": "Kalıcılık (persistence)",
    "defense_evasion": "Savunma atlatma",
    "phishing": "Oltalama (phishing)",
    "reconnaissance": "Keşif (recon)",
    "command_and_control": "C2 bağlantısı",
    "execution": "Çalıştırma",
    "exfil": "Veri sızdırma",
    "test": "Test",
    "test_batch": "Test (toplu)",
    "info": "Bilgi",
    "unknown": "Bilinmeyen",
}


def _on_realtime_alert(record: dict[str, Any]) -> None:
    logger.info("Realtime alert received: %s", record.get("title"))
    REALTIME_QUEUE.put(record)


def drain_realtime_queue() -> list[dict[str, Any]]:
    new_alerts: list[dict[str, Any]] = []
    while True:
        try:
            new_alerts.append(REALTIME_QUEUE.get_nowait())
        except queue.Empty:
            break
    return new_alerts


def init_dashboard() -> None:
    if "alerts" not in st.session_state:
        try:
            st.session_state.alerts = get_alerts(limit=100)
        except Exception:
            logger.exception("Failed to load initial alerts")
            st.session_state.alerts = []
    if "last_rule" not in st.session_state:
        st.session_state.last_rule = None
    if "listener_mode" not in st.session_state:
        st.session_state.listener_mode = start_alert_listener(_on_realtime_alert)


def merge_alerts(new_alerts: list[dict[str, Any]]) -> None:
    if not new_alerts:
        return
    existing_ids = {alert["id"] for alert in st.session_state.alerts}
    for alert in reversed(new_alerts):
        if alert["id"] not in existing_ids:
            st.session_state.alerts.insert(0, alert)
            existing_ids.add(alert["id"])


def split_alerts(alerts: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    active: list[dict[str, Any]] = []
    archived: list[dict[str, Any]] = []
    for alert in alerts:
        status = str(alert.get("status", "open"))
        if status in ARCHIVED_STATUSES:
            archived.append(alert)
        else:
            active.append(alert)
    return active, archived


def count_by_severity(alerts: list[dict[str, Any]], severity: str) -> int:
    return sum(1 for a in alerts if str(a.get("severity", "")).lower() == severity)


def render_alert_feed(
    alerts: list[dict[str, Any]],
    *,
    key_prefix: str,
    limit: int = 15,
    global_soar_active: bool = False,
) -> None:
    if not alerts:
        return
    from src.threat_intel import assess_alert

    for alert in alerts[:limit]:
        try:
            intel = assess_alert(alert)
        except Exception:
            logger.exception("Threat intel assess failed for alert %s", alert.get("id"))
            intel = None
        render_alert_card(
            alert,
            SEVERITY_COLORS,
            global_soar_active=global_soar_active,
            intel=intel,
        )
        alert_id = alert.get("id")
        if not alert_id:
            continue
        cols = st.columns([3, 1])
        with cols[0]:
            current_status = str(alert.get("status", "open"))
            if current_status not in STATUS_OPTIONS:
                current_status = "open"
            new_status = st.selectbox(
                "Durum",
                STATUS_OPTIONS,
                format_func=lambda x: STATUS_TR[x],
                index=STATUS_OPTIONS.index(current_status),
                key=f"{key_prefix}_status_{alert_id}",
                label_visibility="collapsed",
            )
        with cols[1]:
            if st.button("Kaydet", key=f"{key_prefix}_save_{alert_id}", use_container_width=True):
                try:
                    update_alert(alert_id, {"status": new_status})
                    alert["status"] = new_status
                    st.toast(f"Alarm güncellendi: {STATUS_TR.get(new_status, new_status)}")
                    st.rerun()
                except Exception:
                    logger.exception("Failed to update alert %s", alert_id)
                    st.error("Güncelleme başarısız.")


def render_metrics(logs: list, rules: list, alerts: list) -> None:
    active_alerts, archived_alerts = split_alerts(alerts)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("KAYITLI LOG", len(logs), help="Dış kaynaklardan gelen olay kayıtları")
    c2.metric("TESPİT KURALI", len(rules), help="Üretilen sorgu kuralları")
    c3.metric(
        "AÇIK ALARM",
        len(active_alerts),
        help=f"Aktif: {len(active_alerts)} · Arşiv: {len(archived_alerts)} · Toplam: {len(alerts)}",
    )
    c4.metric(
        "KRİTİK (AÇIK)",
        count_by_severity(active_alerts, "critical"),
        help="Sadece açık / inceleniyor durumundaki kritik alarmlar",
    )


def render_threat_intel_card(alerts: list[dict[str, Any]]) -> None:
    """Canlı Tehdit İstihbaratı özet kartı — tüm alarmların IoC durumunu toplar."""
    from src.threat_intel import assess_alert

    panel_title("🛰 CANLI TEHDİT İSTİHBARATI")

    malicious: list[dict[str, Any]] = []
    suspicious = 0
    checked = 0
    for alert in alerts:
        try:
            intel = assess_alert(alert)
        except Exception:
            continue
        if not intel.get("indicators"):
            continue
        checked += 1
        verdict = intel.get("verdict")
        if intel.get("is_malicious"):
            malicious.append(
                {
                    "ioc": intel.get("primary_ioc", "?"),
                    "score": intel.get("risk_score", 0),
                    "source": intel.get("source", "—"),
                    "title": alert.get("title", "Alarm"),
                }
            )
        elif verdict == "suspicious":
            suspicious += 1

    c1, c2, c3 = st.columns(3)
    c1.metric("DEĞERLENDİRİLEN", checked, help="IoC içeren alarm sayısı")
    c2.metric("ZARARLI", len(malicious), help="Bilinen zararlı IoC tespit edilen alarmlar")
    c3.metric("ŞÜPHELİ", suspicious, help="Orta riskli IoC'ler")

    if malicious:
        st.markdown(
            '<p style="color:#ff2d55;font-size:0.8rem;font-weight:700;margin:0.4rem 0 0.2rem 0;">'
            "● Bilinen zararlı göstergeler</p>",
            unsafe_allow_html=True,
        )
        for item in malicious[:5]:
            st.markdown(
                f'<div style="font-size:0.76rem;color:#cbd5e1;padding:0.15rem 0;">'
                f'🔴 <code>{item["ioc"]}</code> · Risk {item["score"]}/100 · '
                f'<span style="color:#64748b;">{item["source"]}</span></div>',
                unsafe_allow_html=True,
            )
    elif checked:
        st.caption("Şu an bilinen zararlı IoC yok — göstergeler temiz/şüpheli.")
    else:
        st.caption("Henüz değerlendirilecek IoC yok.")


def chart_label(log: dict[str, Any]) -> str:
    raw = log.get("event_type") or log.get("source") or "unknown"
    key = str(raw).lower()
    return EVENT_TYPE_TR.get(key, str(raw).replace("_", " "))


def build_traffic_chart(logs: list[dict[str, Any]]):
    if not logs:
        return None
    counter: Counter[str] = Counter()
    for log in logs:
        counter[chart_label(log)] += 1
    ranked = counter.most_common()
    labels = [label for label, _ in ranked]
    values = [count for _, count in ranked]
    colors = [CYBER_CHART_COLORS[i % len(CYBER_CHART_COLORS)] for i in range(len(labels))]
    fig = go.Figure(
        data=[
            go.Bar(
                x=labels,
                y=values,
                text=values,
                textposition="outside",
                textfont=dict(color="#94a3b8", size=12),
                marker=dict(color=colors, line=dict(color="rgba(0,229,255,0.35)", width=1)),
            )
        ]
    )
    fig.update_layout(
        title=dict(text="LOG DAĞILIMI — Olay türlerine göre", font=dict(color="#00e5ff", size=14)),
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#94a3b8", family="JetBrains Mono"),
        height=400,
        margin=dict(l=20, r=20, t=50, b=80),
        bargap=0.35,
        xaxis=dict(gridcolor="rgba(0,229,255,0.08)", tickangle=-25, title="Olay türü"),
        yaxis=dict(gridcolor="rgba(0,229,255,0.08)", title="Adet", dtick=1),
    )
    return fig


def log_label(log: dict[str, Any]) -> str:
    event = log.get("event_type") or "olay"
    host = log.get("hostname") or "bilinmeyen"
    log_id = str(log.get("id", ""))[:8]
    status = "analiz edildi" if log.get("analyzed_at") else "yeni"
    return f"[{status}] {event} @ {host} ({log_id})"


def render_rules_sidebar(limit: int = 8) -> None:
    panel_title("TESPİT KURALLARI")
    try:
        rules = get_rules(limit=limit)
    except Exception:
        logger.exception("Failed to load rules")
        st.error("Kurallar yüklenemedi.")
        return
    if not rules:
        st.caption("Henüz kural yok.")
        return
    for rule in rules:
        sev = rule.get("severity", "—")
        sev_tr = SEVERITY_TR.get(str(sev).lower(), sev)
        color = SEVERITY_COLORS.get(str(sev).lower(), "#64748b")
        with st.expander(f"▸ {rule.get('name', 'Kural')}"):
            st.markdown(
                f'<span style="color:{color};font-size:0.75rem;font-weight:700;">{sev_tr}</span>',
                unsafe_allow_html=True,
            )
            st.caption(get_rule_summary(rule))
            st.caption(get_rule_action_hint(str(rule.get("severity", "medium"))))
            for line in explain_standard(str(rule.get("standard", "")))[:3]:
                st.caption(f"· {line}")
            st.code(rule.get("content", ""), language="sql")


@st.fragment(run_every=timedelta(seconds=2))
def live_alerts_panel() -> None:
    from src.database import get_global_policy

    global_soar_active = get_global_policy()
    mode = get_listener_mode()
    st.session_state.listener_mode = mode
    if mode == "polling":
        try:
            st.session_state.alerts = get_alerts(limit=100)
        except Exception:
            logger.exception("Polling alert refresh failed")
    else:
        incoming = drain_realtime_queue()
        if incoming:
            merge_alerts(incoming)

    active_alerts, archived_alerts = split_alerts(st.session_state.alerts)
    feed_label = "◉ CANLI ALARMLAR" if mode == "websocket" else "◉ ALARMLAR (2 sn yenileme)"
    panel_title(feed_label)

    tab_active, tab_archive = st.tabs(
        [f"🔴 Açık ({len(active_alerts)})", f"📁 Arşiv ({len(archived_alerts)})"]
    )
    with tab_active:
        if not active_alerts:
            st.markdown(
                '<p style="color:#64748b;font-size:0.85rem;">Açık alarm yok. '
                "Dış kaynaktan log geldiğinde burada görünür.</p>",
                unsafe_allow_html=True,
            )
        else:
            st.caption("Açık ve inceleniyor durumundaki alarmlar.")
            render_alert_feed(active_alerts, key_prefix="active", limit=15, global_soar_active=global_soar_active)
    with tab_archive:
        if not archived_alerts:
            st.markdown(
                '<p style="color:#64748b;font-size:0.85rem;">Arşiv boş.</p>',
                unsafe_allow_html=True,
            )
        else:
            st.caption("Çözüldü ve yanlış alarm olarak kapatılan kayıtlar.")
            render_alert_feed(archived_alerts, key_prefix="archive", limit=20, global_soar_active=global_soar_active)


def get_analysis_mode_label() -> str:
    mode = resolve_analysis_mode()
    return "Yapay zeka (Cursor)" if mode == "cursor" else "Otomatik analiz"
