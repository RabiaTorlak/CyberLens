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
from src.database import get_alerts, get_logs, get_rule_for_log, get_rules, update_alert
from src.logging_config import get_logger
from src.pipeline import Pipeline
from src.realtime_listener import get_listener_mode, start_alert_listener
from src.ui.cyber_theme import inject_cyber_theme, panel_title, render_alert_card, render_header
from src.ui.rule_explainer import (
    RULE_GENERATOR_HELP,
    explain_standard,
    get_rule_action_hint,
    get_rule_summary,
    summarize_kql,
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
            st.session_state.alerts = get_alerts(limit=100)
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


def _split_alerts(alerts: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    active: list[dict[str, Any]] = []
    archived: list[dict[str, Any]] = []
    for alert in alerts:
        status = str(alert.get("status", "open"))
        if status in ARCHIVED_STATUSES:
            archived.append(alert)
        else:
            active.append(alert)
    return active, archived


def _render_alert_feed(alerts: list[dict[str, Any]], *, key_prefix: str, limit: int = 15) -> None:
    if not alerts:
        return

    for alert in alerts[:limit]:
        render_alert_card(alert, SEVERITY_COLORS)
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


def _render_metrics(logs: list, rules: list, alerts: list) -> None:
    active_alerts, archived_alerts = _split_alerts(alerts)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("KAYITLI LOG", len(logs), help="Veritabanındaki olay kayıtları")
    c2.metric("TESPİT KURALI", len(rules), help="Üretilen sorgu kuralları")
    c3.metric(
        "AÇIK ALARM",
        len(active_alerts),
        help=f"Aktif: {len(active_alerts)} · Arşiv: {len(archived_alerts)} · Toplam: {len(alerts)}",
    )
    c4.metric(
        "KRİTİK (AÇIK)",
        _count_by_severity(active_alerts, "critical"),
        help="Sadece açık / inceleniyor durumundaki kritik alarmlar",
    )


def _chart_label(log: dict[str, Any]) -> str:
    """Grafik için okunabilir etiket — kaynak değil olay türü."""
    raw = log.get("event_type") or log.get("source") or "unknown"
    key = str(raw).lower()
    return EVENT_TYPE_TR.get(key, str(raw).replace("_", " "))


def _build_traffic_chart(logs: list[dict[str, Any]]):
    if not logs:
        return None

    counter: Counter[str] = Counter()
    for log in logs:
        counter[_chart_label(log)] += 1

    # En çok görülen olaylar önce; tek renk yeşil kalmasın diye sıralı renk
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
                marker=dict(
                    color=colors,
                    line=dict(color="rgba(0,229,255,0.35)", width=1),
                ),
            )
        ]
    )
    fig.update_layout(
        title=dict(
            text="LOG DAĞILIMI — Olay türlerine göre",
            font=dict(color="#00e5ff", size=14),
        ),
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


def _log_label(log: dict[str, Any]) -> str:
    event = log.get("event_type") or "olay"
    host = log.get("hostname") or "bilinmeyen"
    log_id = str(log.get("id", ""))[:8]
    if log.get("analyzed_at"):
        status = "analiz edildi"
    else:
        status = "yeni"
    return f"[{status}] {event} @ {host} ({log_id})"


def _render_rule_block(rule: dict[str, Any], title: str = "SON ÜRETİLEN KURAL") -> None:
    name = rule.get("name", "Tespit kuralı")
    severity = str(rule.get("severity", "medium")).lower()
    severity_tr = SEVERITY_TR.get(severity, rule.get("severity", "—"))
    summary = get_rule_summary(rule)
    action_hint = get_rule_action_hint(severity)
    standard_lines = explain_standard(str(rule.get("standard", "")))
    kql_steps = summarize_kql(str(rule.get("content", "")))

    st.markdown('<div class="cyber-terminal">', unsafe_allow_html=True)
    st.markdown(f"##### ▸ {title}")
    st.markdown(f"**Kural adı:** {name}")

    st.markdown(
        f"""
        <div style="background:rgba(0,229,255,0.06); border-left:3px solid #00e5ff;
        padding:0.75rem 1rem; margin:0.75rem 0; border-radius:6px;">
        <p style="margin:0 0 0.4rem 0; color:#94a3b8; font-size:0.85rem;">
        <strong style="color:#00e5ff;">Ne işe yarar?</strong><br>{summary}
        </p>
        <p style="margin:0; color:#64748b; font-size:0.8rem;">
        <strong>Ne yapmalısın?</strong> {action_hint}
        </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    m1, m2 = st.columns(2)
    m1.markdown(f"**Önem:** `{severity_tr}`")
    m2.markdown(f"**Standart etiketleri:** `{rule.get('standard', '—')}`")

    if standard_lines:
        with st.expander("📚 Standartlar ne anlama geliyor?", expanded=False):
            for line in standard_lines:
                st.markdown(f"- {line}")

    with st.expander("🔍 Bu sorgu ne yapıyor? (sade dil)", expanded=True):
        for step in kql_steps:
            st.markdown(f"- {step}")

    st.markdown("**KQL sorgusu** *(gerçek SIEM'e yapıştırılabilir demo)*")
    st.code(rule.get("content", ""), language="sql")
    st.markdown("</div>", unsafe_allow_html=True)


@st.fragment(run_every=timedelta(seconds=2))
def live_alerts_panel() -> None:
    mode = get_listener_mode()
    st.session_state.listener_mode = mode

    if mode == "polling":
        try:
            st.session_state.alerts = get_alerts(limit=100)
        except Exception:
            logger.exception("Polling alert refresh failed")
    else:
        incoming = _drain_realtime_queue()
        if incoming:
            _merge_alerts(incoming)

    active_alerts, archived_alerts = _split_alerts(st.session_state.alerts)

    feed_label = "◉ CANLI ALARMLAR" if mode == "websocket" else "◉ ALARMLAR (2 sn yenileme)"
    panel_title(feed_label)

    tab_active, tab_archive = st.tabs(
        [
            f"🔴 Açık ({len(active_alerts)})",
            f"📁 Arşiv ({len(archived_alerts)})",
        ]
    )

    with tab_active:
        if not active_alerts:
            st.markdown(
                '<p style="color:#64748b;font-size:0.85rem;">Açık alarm yok. Yeni log analiz ettiğinde burada görünür.</p>',
                unsafe_allow_html=True,
            )
        else:
            st.caption("Açık ve inceleniyor durumundaki alarmlar.")
            _render_alert_feed(active_alerts, key_prefix="active", limit=15)

    with tab_archive:
        if not archived_alerts:
            st.markdown(
                '<p style="color:#64748b;font-size:0.85rem;">Arşiv boş. Çözüldü veya yanlış alarm işaretlenenler buraya taşınır.</p>',
                unsafe_allow_html=True,
            )
        else:
            st.caption("Çözüldü ve yanlış alarm olarak kapatılan kayıtlar.")
            _render_alert_feed(archived_alerts, key_prefix="archive", limit=20)


def _sidebar_controls() -> None:
    st.markdown("### ⚙ KONTROL PANELİ")
    st.markdown(
        '<p style="color:#64748b;font-size:0.75rem;">Analiz ve kural yönetimi</p>',
        unsafe_allow_html=True,
    )

    from lab.poc_lab_simulator import EVENT_CATALOG, generate_sample_events

    log_count = st.slider(
        "Gönderilecek log sayısı",
        min_value=1,
        max_value=12,
        value=6,
        help=f"{len(EVENT_CATALOG)} farklı saldırı senaryosundan her seferinde rastgele seçilir.",
    )

    if st.button("📥 Yeni test logları gönder", use_container_width=True):
        with st.spinner("Test logları ekleniyor..."):
            try:
                batch = generate_sample_events(log_count)
                count = Pipeline().ingest_logs(batch)
                types = ", ".join(
                    sorted({EVENT_TYPE_TR.get(e["event"], e["event"]) for e in batch})
                )
                st.success(f"{count} yeni log eklendi: {types}")
                st.rerun()
            except Exception:
                logger.exception("Sample log ingest failed")
                st.error("Log gönderilemedi.")

    if st.button("▶ LOGLARI ANALİZ ET", use_container_width=True, type="primary"):
        with st.spinner("Loglar taranıyor..."):
            try:
                result = Pipeline().analyze_unprocessed(limit=50)
                st.success(
                    f"+{result.rules_created} yeni kural · +{result.alerts_created} yeni alarm"
                )
                st.session_state.alerts = get_alerts(limit=100)
                st.rerun()
            except Exception:
                logger.exception("Pipeline analyze failed")
                st.error("Analiz başarısız.")

    st.markdown("---")
    panel_title("TESPİT KURALLARI")

    try:
        rules = get_rules(limit=8)
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


def main() -> None:
    st.set_page_config(
        page_title="LOGTUT — Güvenlik Paneli",
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
            st.caption("Grafik için log bekleniyor...")
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("---")
    panel_title("◈ KURAL ÜRETİCİ")

    with st.expander("ℹ Tespit kuralı nedir? Buradan oku", expanded=False):
        st.markdown(RULE_GENERATOR_HELP)

    if not logs:
        st.warning("Log yok. Önce şunu çalıştır: python lab/poc_lab_simulator.py --full")
        return

    col_sel, col_action = st.columns([2, 1])
    with col_sel:
        log_options = {_log_label(log): log for log in logs}
        selected_label = st.selectbox("Analiz edilecek log", list(log_options.keys()))
        selected_log = log_options[selected_label]

    selected_id = str(selected_log.get("id") or "")
    existing_rule = get_rule_for_log(selected_id) if selected_id else None
    if existing_rule:
        st.caption("Bu log daha önce analiz edilmiş — mevcut kural aşağıda.")
        _render_rule_block(existing_rule, title="MEVCUT KURAL")

    with col_action:
        st.markdown("<br>", unsafe_allow_html=True)
        generate = st.button("⚡ KURAL ÜRET", type="primary", use_container_width=True)

    mode_text = "Yapay zeka (Cursor)" if analysis_mode == "cursor" else "Otomatik analiz"
    st.caption(f"Analiz motoru: **{mode_text}**")

    if generate:
        with st.spinner("Tehdit analizi yapılıyor..."):
            try:
                result = AIEngine().analyze_and_save(selected_log, selected_log.get("id"))
            except Exception as exc:
                logger.exception("KQL rule generation failed")
                st.error(f"Analiz hatası: {exc}")
                return

        if result is None:
            st.error("Beklenmeyen hata: analiz sonucu alınamadı.")
            return

        status = result.get("status")
        rule = result.get("rule")
        alert = result.get("alert")

        if status == "no_threat":
            st.warning("Bu logda tehdit tespit edilmedi.")
            return

        if status == "already_exists" and rule:
            st.session_state.last_rule = rule
            st.session_state.alerts = get_alerts(limit=100)
            st.info(f"Bu log zaten analiz edilmiş. Mevcut kural: **{rule['name']}**")
            st.rerun()
            return

        if status == "created" and rule:
            st.session_state.last_rule = rule
            st.session_state.alerts = get_alerts(limit=100)
            st.success(f"Yeni kural kaydedildi: **{rule['name']}**")
            if alert:
                st.info(f"Yeni alarm oluştu: **{alert['title']}**")
            st.rerun()
            return

        st.error("Analiz tamamlandı ama kural oluşturulamadı.")

    if st.session_state.last_rule and not existing_rule:
        rule = st.session_state.last_rule
        if isinstance(rule, dict) and "rule" in rule:
            rule = rule["rule"]
        if isinstance(rule, dict):
            _render_rule_block(rule)


if __name__ == "__main__":
    main()
