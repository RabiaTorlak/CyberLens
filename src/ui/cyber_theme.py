"""Cybersecurity SOC dashboard theme for Streamlit."""

from __future__ import annotations

import html as html_lib
import re
from typing import Any

CYBER_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Orbitron:wght@500;700&display=swap');

:root {
    --cyber-bg: #0a0e14;
    --cyber-panel: #0f1623;
    --cyber-border: #1e3a5f;
    --cyber-green: #00ff88;
    --cyber-cyan: #00e5ff;
    --cyber-red: #ff2d55;
    --cyber-amber: #ffb020;
    --cyber-text: #cbd5e1;
    --cyber-muted: #64748b;
}

.stApp {
    background: radial-gradient(ellipse at 20% 0%, #0f1a2e 0%, var(--cyber-bg) 45%),
                radial-gradient(ellipse at 80% 100%, #0a1f1a 0%, var(--cyber-bg) 50%),
                var(--cyber-bg);
}

.stApp::before {
    content: "";
    position: fixed;
    inset: 0;
    background-image:
        linear-gradient(rgba(0, 255, 136, 0.03) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0, 255, 136, 0.03) 1px, transparent 1px);
    background-size: 48px 48px;
    pointer-events: none;
    z-index: 0;
}

.block-container {
    padding-top: 1.5rem;
    max-width: 1400px;
}

h1, h2, h3, .cyber-title {
    font-family: 'Orbitron', sans-serif !important;
    letter-spacing: 0.06em;
}

code, pre, .stCodeBlock {
    font-family: 'JetBrains Mono', monospace !important;
}

[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0c1220 0%, #080d16 100%);
    border-right: 1px solid var(--cyber-border);
}

[data-testid="stSidebar"] .stMarkdown h1,
[data-testid="stSidebar"] .stMarkdown h2,
[data-testid="stSidebar"] .stMarkdown h3 {
    color: var(--cyber-cyan) !important;
}

div[data-testid="stMetric"] {
    background: linear-gradient(135deg, rgba(0, 255, 136, 0.08), rgba(0, 229, 255, 0.05));
    border: 1px solid rgba(0, 255, 136, 0.25);
    border-radius: 10px;
    padding: 0.75rem 1rem;
    box-shadow: 0 0 20px rgba(0, 255, 136, 0.06);
}

div[data-testid="stMetric"] label {
    color: var(--cyber-muted) !important;
    font-size: 0.75rem !important;
    text-transform: uppercase;
    letter-spacing: 0.08em;
}

div[data-testid="stMetric"] [data-testid="stMetricValue"] {
    font-family: 'Orbitron', sans-serif !important;
    color: var(--cyber-green) !important;
}

.stButton > button[kind="primary"] {
    background: linear-gradient(90deg, #00ff88 0%, #00c896 100%) !important;
    color: #0a0e14 !important;
    border: none !important;
    font-weight: 700 !important;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    box-shadow: 0 0 18px rgba(0, 255, 136, 0.35);
}

.stButton > button[kind="primary"]:hover {
    box-shadow: 0 0 28px rgba(0, 255, 136, 0.55);
    filter: brightness(1.05);
}

.stButton > button[kind="secondary"] {
    border: 1px solid var(--cyber-cyan) !important;
    color: var(--cyber-cyan) !important;
    background: transparent !important;
}

.cyber-header {
    border: 1px solid rgba(0, 229, 255, 0.35);
    border-radius: 12px;
    padding: 1.25rem 1.5rem;
    margin-bottom: 1.25rem;
    background: linear-gradient(135deg, rgba(15, 22, 35, 0.95), rgba(10, 14, 20, 0.9));
    box-shadow: 0 0 30px rgba(0, 229, 255, 0.08), inset 0 1px 0 rgba(0, 255, 136, 0.1);
}

.cyber-header h1 {
    margin: 0;
    font-size: 1.65rem;
    background: linear-gradient(90deg, #00ff88, #00e5ff);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}

.cyber-header p {
    margin: 0.35rem 0 0;
    color: var(--cyber-muted);
    font-size: 0.85rem;
    letter-spacing: 0.04em;
}

.cyber-badge {
    display: inline-block;
    padding: 0.2rem 0.55rem;
    border-radius: 4px;
    font-size: 0.65rem;
    font-weight: 700;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    margin-right: 0.4rem;
}

.cyber-badge-live {
    background: rgba(255, 45, 85, 0.15);
    color: #ff2d55;
    border: 1px solid rgba(255, 45, 85, 0.5);
    animation: pulse 2s infinite;
}

.cyber-badge-secure {
    background: rgba(0, 255, 136, 0.12);
    color: #00ff88;
    border: 1px solid rgba(0, 255, 136, 0.4);
}

@keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.55; }
}

.cyber-panel {
    border: 1px solid var(--cyber-border);
    border-radius: 10px;
    padding: 1rem 1.1rem;
    background: rgba(15, 22, 35, 0.75);
    margin-bottom: 0.75rem;
}

.cyber-panel-title {
    font-family: 'Orbitron', sans-serif;
    color: var(--cyber-cyan);
    font-size: 0.8rem;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    margin-bottom: 0.75rem;
    padding-bottom: 0.5rem;
    border-bottom: 1px solid rgba(0, 229, 255, 0.2);
}

.cyber-alert {
    border-left: 3px solid;
    padding: 0.85rem 1rem;
    margin-bottom: 0.65rem;
    background: rgba(8, 13, 22, 0.85);
    border-radius: 0 8px 8px 0;
    transition: box-shadow 0.2s;
}

.cyber-alert:hover {
    box-shadow: 0 0 16px rgba(0, 229, 255, 0.12);
}

.cyber-alert-title {
    color: #f1f5f9;
    font-weight: 600;
    font-size: 0.95rem;
}

.cyber-alert-desc {
    color: var(--cyber-text);
    font-size: 0.82rem;
    margin-top: 0.3rem;
    line-height: 1.45;
}

.cyber-alert-meta {
    color: var(--cyber-muted);
    font-size: 0.7rem;
    margin-top: 0.4rem;
    font-family: 'JetBrains Mono', monospace;
}

.cyber-terminal {
    background: #050810 !important;
    border: 1px solid rgba(0, 255, 136, 0.3) !important;
    border-radius: 8px !important;
    box-shadow: inset 0 0 20px rgba(0, 255, 136, 0.05);
}

.cyber-status-dot {
    display: inline-block;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: #00ff88;
    box-shadow: 0 0 8px #00ff88;
    margin-right: 6px;
    animation: pulse 2s infinite;
}

hr {
    border-color: rgba(0, 229, 255, 0.15) !important;
}

.stExpander {
    border: 1px solid var(--cyber-border) !important;
    border-radius: 8px !important;
    background: rgba(10, 14, 20, 0.6) !important;
}

div[data-testid="stExpanderDetails"] {
    border-top: 1px solid rgba(0, 229, 255, 0.15);
}
</style>
"""


def inject_cyber_theme() -> None:
    import streamlit as st

    st.markdown(CYBER_CSS, unsafe_allow_html=True)


def render_header(analysis_mode: str) -> None:
    import streamlit as st

    mode_label = "Yapay Zeka" if analysis_mode == "cursor" else "Otomatik Analiz"
    st.markdown(
        f"""
        <div class="cyber-header">
            <span class="cyber-badge cyber-badge-live">● CANLI İZLEME</span>
            <span class="cyber-badge cyber-badge-secure">TEHDİT TESPİT</span>
            <h1>⚡ LOGTUT — GÜVENLİK İZLEME MERKEZİ</h1>
            <p>
                <span class="cyber-status-dot"></span>
                Anlık alarm takibi · Bulut veritabanı · Mod: {mode_label}
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _esc(text: Any) -> str:
    return html_lib.escape(str(text if text is not None else ""))


def _plain_field(text: Any) -> str:
    """Kullanıcı metnini güvenli düz metne çevir (bozuk HTML parçalarını temizle)."""
    raw = str(text if text is not None else "")
    raw = re.sub(r"<[^>]+>", " ", raw)
    raw = re.sub(r"\s+", " ", raw).strip()
    return _esc(raw or "—")


def render_alert_card(
    alert: dict,
    severity_colors: dict[str, str],
    *,
    global_soar_active: bool = False,
    intel: dict | None = None,
) -> None:
    import streamlit as st

    severity = str(alert.get("severity", "medium")).lower()
    color = severity_colors.get(severity, "#64748b")
    severity_tr = {"critical": "Kritik", "high": "Yüksek", "medium": "Orta", "low": "Düşük"}.get(severity, severity)
    status_tr = {"open": "Açık", "investigating": "İnceleniyor", "resolved": "Çözüldü", "false_positive": "Yanlış alarm"}.get(
        str(alert.get("status", "open")), alert.get("status", "open")
    )
    title = _plain_field(alert.get("title", "Başlıksız alarm"))
    raw_desc = str(alert.get("description") or "—")
    raw_desc = re.sub(r"<[^>]+>", " ", raw_desc)
    raw_desc = re.sub(r"[ \t]+", " ", raw_desc)
    description = _esc(raw_desc.strip()).replace("\n", "<br>")
    created = _esc(alert.get("created_at", ""))

    metadata = alert.get("metadata") or {}
    soar = metadata.get("soar") if isinstance(metadata, dict) else None

    soar_badge_html = ""
    soar_detail_html = ""
    if global_soar_active and soar and soar.get("auto_response"):
        soar_badge_html = (
            '<span class="cyber-badge" style="color:#ffb020; border:1px solid #ffb020; '
            'background:rgba(255,176,32,0.12); margin-left:0.35rem;">⚡ OTOMATİK MÜDAHALE</span>'
        )
        details = soar.get("action_details") or [soar.get("action_summary", "Otomatik müdahale uygulandı")]
        detail_lines = "<br>".join(f"▸ {_esc(line)}" for line in details[:4])
        soar_detail_html = (
            '<div style="margin-top:0.5rem; padding:0.5rem 0.65rem; border-radius:6px; '
            'background:rgba(255,176,32,0.08); border:1px solid rgba(255,176,32,0.25); '
            'font-size:0.78rem; color:#fbbf24;">'
            f"<strong>Otomatik Müdahale Devrede</strong><br>{detail_lines}"
            "</div>"
        )
    elif global_soar_active and not soar:
        soar_detail_html = (
            '<div style="margin-top:0.4rem; font-size:0.75rem; color:#64748b;">'
            "SOAR modu aktif — bu alarm henüz otomatik işlenmedi."
            "</div>"
        )

    # --- Threat Intelligence: risk skoru, istihbarat notu, zararlı çerçevesi ---
    intel_badge_html = ""
    intel_note_html = ""
    card_extra_style = ""
    if intel and intel.get("indicators"):
        score = int(intel.get("risk_score", 0))
        verdict = str(intel.get("verdict", "unknown"))
        is_malicious = bool(intel.get("is_malicious"))
        is_critical = bool(intel.get("is_critical"))
        note = _esc(intel.get("note", ""))

        if score >= 75 or is_critical:
            ti_color = "#ff2d55"
        elif score >= 30:
            ti_color = "#ffb020"
        elif verdict == "internal":
            ti_color = "#3b82f6"
        else:
            ti_color = "#00ff88"

        critical_badge = (
            '<span class="cyber-badge" style="color:#fff;border:1px solid #ff2d55;'
            'background:#ff2d55;margin-left:0.35rem;font-weight:700;">🚨 KRİTİK</span>'
            if is_critical
            else ""
        )
        intel_badge_html = (
            critical_badge
            + f'<span class="cyber-badge" style="color:{ti_color};border:1px solid {ti_color};'
            f'background:rgba(0,0,0,0.3);margin-left:0.35rem;">🛰 Risk {score}/100</span>'
        )
        intel_note_html = (
            f'<div style="margin-top:0.45rem;padding:0.4rem 0.6rem;border-radius:6px;'
            f'background:rgba(0,0,0,0.25);border:1px solid {ti_color};'
            f'font-size:0.74rem;color:{ti_color};">'
            f"<strong>İstihbarat:</strong> {note}</div>"
        )
        if is_malicious or is_critical:
            card_extra_style = (
                "border:2px solid #ff2d55;box-shadow:0 0 14px rgba(255,45,85,0.45);"
            )

    parts = [
        f'<div class="cyber-alert" style="border-left-color:{color};{card_extra_style}">',
        f'<span class="cyber-badge" style="color:{color};border:1px solid {color};background:rgba(0,0,0,0.3);">{severity_tr}</span>',
        f'<span style="color:#64748b;font-size:0.75rem;margin-left:0.3rem;">{status_tr}</span>',
        soar_badge_html,
        intel_badge_html,
        f'<div class="cyber-alert-title">{title}</div>',
        f'<div class="cyber-alert-desc">{description}</div>',
        intel_note_html,
        soar_detail_html,
        f'<div class="cyber-alert-meta">{created}</div>',
        "</div>",
    ]
    st.markdown("".join(parts), unsafe_allow_html=True)


def panel_title(text: str) -> None:
    import streamlit as st

    st.markdown(f'<div class="cyber-panel-title">{text}</div>', unsafe_allow_html=True)
