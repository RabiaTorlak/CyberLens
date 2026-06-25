"""SOC Güvenlik Paneli — sadece izleme ve analiz."""

from __future__ import annotations

import streamlit as st

from src.ai_engine import AIEngine
from src.database import get_alerts, get_global_policy, get_logs, get_rule_for_log, get_rules, set_global_policy
from src.forensic_engine import build_timeline_for_alert
from src.logging_config import get_logger
from src.pipeline import Pipeline
from src.ui.cyber_theme import inject_cyber_theme, panel_title, render_header
from src.ui.dashboard_common import (
    SEVERITY_TR,
    build_traffic_chart,
    drain_realtime_queue,
    get_analysis_mode_label,
    init_dashboard,
    live_alerts_panel,
    log_label,
    merge_alerts,
    render_metrics,
    render_rules_sidebar,
    render_threat_intel_card,
)
from src.ui.rule_explainer import (
    RULE_GENERATOR_HELP,
    explain_standard,
    get_rule_action_hint,
    get_rule_summary,
    summarize_kql,
)

logger = get_logger("soc_page")

CATEGORY_STYLE: dict[str, tuple[str, str]] = {
    "access": ("#00e5ff", "🔑"),
    "recon": ("#3b82f6", "🔍"),
    "delivery": ("#7c3aed", "📥"),
    "execution": ("#ffb020", "⚙"),
    "escalation": ("#ff6b35", "⬆"),
    "persistence": ("#a855f7", "📌"),
    "evasion": ("#64748b", "🥷"),
    "movement": ("#ff2d55", "↔"),
    "collection": ("#22d3ee", "📂"),
    "c2": ("#f43f5e", "📡"),
    "exfil": ("#ff2d55", "📤"),
    "network": ("#94a3b8", "🌐"),
}


def _render_timeline_event(event: dict, is_last: bool) -> None:
    color, icon = CATEGORY_STYLE.get(event["category"], ("#94a3b8", "•"))
    pivot = event.get("is_pivot")
    border = "2px solid #ff2d55" if pivot else f"1px solid {color}"
    glow = "box-shadow:0 0 12px rgba(255,45,85,0.4);" if pivot else ""
    pivot_badge = (
        '<span style="background:#ff2d55;color:#fff;font-size:0.6rem;padding:1px 6px;'
        'border-radius:4px;margin-left:0.4rem;">TETİKLEYEN OLAY</span>'
        if pivot
        else ""
    )
    line = (
        '<div style="width:2px;height:22px;background:rgba(148,163,184,0.3);'
        'margin-left:13px;"></div>'
        if not is_last
        else ""
    )
    parts = [
        '<div style="display:flex;align-items:flex-start;gap:0.6rem;">',
        f'<div style="min-width:28px;height:28px;border-radius:50%;border:{border};{glow}'
        f'background:rgba(0,0,0,0.4);display:flex;align-items:center;justify-content:center;'
        f'font-size:0.8rem;">{icon}</div>',
        '<div style="flex:1;padding-bottom:0.3rem;">',
        f'<span style="color:{color};font-weight:700;font-size:0.85rem;">{event["event_label"]}</span>',
        pivot_badge,
        f'<div style="color:#cbd5e1;font-size:0.78rem;margin-top:0.15rem;">'
        f'⏱ {event["date_display"]} {event["time_display"]} · '
        f'💻 {event["hostname"]} · 👤 {event["username"]}</div>',
        f'<div style="color:#64748b;font-size:0.72rem;margin-top:0.1rem;font-family:monospace;">'
        f'{event["summary"]}'
        + (f' · MITRE {event["technique"]}' if event.get("technique") else "")
        + "</div>",
        "</div>",
        "</div>",
    ]
    st.markdown("".join(parts), unsafe_allow_html=True)
    if line:
        st.markdown(line, unsafe_allow_html=True)


def _render_forensic_timeline(alerts: list[dict]) -> None:
    panel_title("🕓 ADLİ ZAMAN ÇİZELGESİ (Forensic Timeline)")
    st.caption(
        "Bir alarm seç → saldırganın (host/kullanıcı) tüm hareketlerini "
        "zaman sırasına göre yeniden kur."
    )

    if not alerts:
        st.info("Henüz alarm yok. Önce Saldırı Lab'dan log gönderip analiz et.")
        return

    def _alert_label(a: dict) -> str:
        sev = SEVERITY_TR.get(str(a.get("severity", "")).lower(), a.get("severity", "—"))
        title = a.get("title", "Alarm")
        created = str(a.get("created_at", ""))[:19].replace("T", " ")
        return f"[{sev}] {title} · {created}"

    options = {_alert_label(a): a for a in alerts}
    col_sel, col_btn = st.columns([3, 1])
    with col_sel:
        selected_label = st.selectbox(
            "İncelenecek alarm",
            list(options.keys()),
            key="timeline_alert_select",
        )
    with col_btn:
        st.markdown("<br>", unsafe_allow_html=True)
        show = st.button("🕓 Timeline Gör", type="primary", use_container_width=True)

    selected_alert = options.get(selected_label)
    if show and selected_alert:
        st.session_state.timeline_alert_id = str(selected_alert.get("id"))

    timeline_id = st.session_state.get("timeline_alert_id")
    if not timeline_id:
        return

    with st.spinner("Saldırgan hareketleri zaman çizelgesine diziliyor..."):
        try:
            data = build_timeline_for_alert(timeline_id)
        except Exception:
            logger.exception("Timeline build failed for %s", timeline_id)
            st.error("Zaman çizelgesi oluşturulamadı.")
            return

    if not data.get("alert"):
        st.warning("Alarm bulunamadı.")
        return

    identity = data.get("identity", {})
    events = data.get("events", [])
    host = identity.get("hostname") or "bilinmeyen"
    user = identity.get("username") or "bilinmeyen"

    st.markdown(
        f"""
        <div style="background:rgba(255,45,85,0.06);border-left:3px solid #ff2d55;
        padding:0.6rem 0.9rem;border-radius:6px;margin:0.5rem 0;">
        <span style="color:#ff2d55;font-weight:700;">🎯 Saldırgan profili</span><br>
        <span style="color:#cbd5e1;font-size:0.85rem;">
        💻 Host: <strong>{host}</strong> · 👤 Kullanıcı: <strong>{user}</strong> ·
        📊 Toplam olay: <strong>{len(events)}</strong></span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if not events:
        st.info("Bu saldırgana ait başka log bulunamadı.")
        return

    st.markdown('<div class="cyber-terminal" style="padding:1rem;">', unsafe_allow_html=True)
    for idx, event in enumerate(events):
        _render_timeline_event(event, is_last=(idx == len(events) - 1))
    st.markdown("</div>", unsafe_allow_html=True)

    if st.button("Zaman çizelgesini kapat", key="timeline_close"):
        st.session_state.timeline_alert_id = None
        st.rerun()


def _render_rule_block(rule: dict, title: str = "SON ÜRETİLEN KURAL") -> None:
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


def _sidebar_soc() -> None:
    st.markdown("### ⚙ SOC KONTROL")
    st.markdown(
        '<p style="color:#64748b;font-size:0.75rem;">Gelen logları işle ve kuralları yönet</p>',
        unsafe_allow_html=True,
    )

    try:
        soar_enabled = get_global_policy()
    except Exception:
        logger.exception("Failed to read global_policy")
        soar_enabled = False
        st.warning("SOAR ayarı okunamadı. Migration 005 uygulandı mı?")

    new_soar = st.toggle(
        "⚡ OTOMATİK MÜDAHALE (SOAR) MODU",
        value=soar_enabled,
        help=(
            "Açıkken tehdit tespit edildiğinde analist onayı beklemeden "
            "response_engine playbook aksiyonları otomatik çalışır."
        ),
    )
    if new_soar != soar_enabled:
        try:
            set_global_policy(new_soar)
            st.toast("SOAR modu güncellendi: " + ("Açık" if new_soar else "Kapalı"))
            st.rerun()
        except Exception:
            logger.exception("Failed to set global_policy")
            st.error("SOAR ayarı kaydedilemedi.")

    if new_soar:
        st.markdown(
            """
            <div style="padding:0.6rem 0.75rem; border-radius:8px; margin-bottom:0.75rem;
            background:rgba(255,176,32,0.1); border:1px solid rgba(255,176,32,0.35);">
            <span style="color:#ffb020; font-size:0.8rem; font-weight:700;">
            ● Otomatik Müdahale Devrede
            </span>
            <p style="color:#94a3b8; font-size:0.75rem; margin:0.35rem 0 0 0;">
            Yeni alarmlar playbook ile otomatik işlenir (IP block, host izole vb.)
            </p>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.info(
        "Loglar **dış kaynaklardan** gelir (firewall, sunucu, poc-lab vb.). "
        "Test logu göndermek için sol menüden **🧪 Saldırı Lab** sayfasına git."
    )
    if st.button("▶ BEKLEYEN LOGLARI ANALİZ ET", use_container_width=True, type="primary"):
        with st.spinner("Gelen loglar taranıyor..."):
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
    render_rules_sidebar()


def render_soc_page() -> None:
    inject_cyber_theme()
    init_dashboard()
    merge_alerts(drain_realtime_queue())

    from src.ai_engine import resolve_analysis_mode

    render_header(resolve_analysis_mode())

    try:
        logs = get_logs(limit=200)
        rules = get_rules(limit=100)
        alerts = st.session_state.alerts
    except Exception:
        logger.exception("Failed to load dashboard data")
        logs, rules, alerts = [], [], []

    render_metrics(logs, rules, alerts)

    with st.sidebar:
        _sidebar_soc()

    st.markdown('<div class="cyber-panel">', unsafe_allow_html=True)
    render_threat_intel_card(alerts)
    st.markdown("</div>", unsafe_allow_html=True)

    col_feed, col_chart = st.columns([1, 1.15])
    with col_feed:
        st.markdown('<div class="cyber-panel">', unsafe_allow_html=True)
        live_alerts_panel()
        st.markdown("</div>", unsafe_allow_html=True)
    with col_chart:
        st.markdown('<div class="cyber-panel">', unsafe_allow_html=True)
        chart = build_traffic_chart(logs)
        if chart:
            st.plotly_chart(chart, use_container_width=True)
        else:
            st.caption("Henüz log yok — Saldırı Lab'dan test verisi gönder.")
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("---")
    st.markdown('<div class="cyber-panel">', unsafe_allow_html=True)
    _render_forensic_timeline(alerts)
    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("---")
    panel_title("◈ KURAL ÜRETİCİ")
    with st.expander("ℹ Tespit kuralı nedir? Buradan oku", expanded=False):
        st.markdown(RULE_GENERATOR_HELP)

    if not logs:
        st.warning(
            "Henüz log yok. Sol menüden **🧪 Saldırı Lab** sayfasına gidip test logları gönder, "
            "sonra burada **Bekleyen logları analiz et** butonuna bas."
        )
        return

    col_sel, col_action = st.columns([2, 1])
    with col_sel:
        log_options = {log_label(log): log for log in logs}
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

    st.caption(f"Analiz motoru: **{get_analysis_mode_label()}**")

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
