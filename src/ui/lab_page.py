"""Saldırı Lab (poc-lab) — dış sistem simülatörü, log üretir."""

from __future__ import annotations

import streamlit as st

from lab.poc_lab_simulator import EVENT_CATALOG, generate_sample_events
from src.logging_config import get_logger
from src.pipeline import Pipeline
from src.ui.cyber_theme import inject_cyber_theme
from src.ui.dashboard_common import EVENT_TYPE_TR

logger = get_logger("lab_page")

LAB_INTRO = """
Bu sayfa **ayrı bir sistemdir** — gerçek dünyada saldırgan ağı, test ortamı veya müşteri sunucusu gibi düşün.

| Rol | Sistem |
|---|---|
| **Burada (Saldırı Lab)** | Sahte saldırı olayları **üretir** ve log olarak gönderir |
| **Güvenlik Paneli** | Gelen logları **yakalar**, analiz eder, alarm üretir |

Loglar Supabase veritabanına yazılır — tıpkı gerçek ortamda SIEM'e akması gibi.
"""


def _render_lab_header() -> None:
    st.markdown(
        """
        <div class="cyber-header" style="border-color: rgba(255,176,32,0.4);">
            <span class="cyber-badge" style="color:#ffb020; border-color:#ffb020; background:rgba(255,176,32,0.1);">
                ● DIŞ KAYNAK SİMÜLATÖRÜ
            </span>
            <span class="cyber-badge" style="color:#ff6b35; border-color:#ff6b35; background:rgba(255,107,53,0.1);">
                poc-lab
            </span>
            <h1>🧪 SALDIRI LAB</h1>
            <p style="color:#94a3b8;">
                Test saldırı senaryoları üret · Logları SOC platformuna gönder
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_lab_page() -> None:
    inject_cyber_theme()
    _render_lab_header()

    st.markdown(LAB_INTRO)

    st.markdown(
        """
        ```
        [ Saldırı Lab ]  ──log gönder──▶  [ Supabase ]  ◀──yakala──  [ Güvenlik Paneli ]
              ↑                                              ↑
         Sen buradasın                                  Analiz & alarm
        ```
        """
    )

    col_ctrl, col_info = st.columns([1, 1.1])

    with col_ctrl:
        st.markdown("### 📡 Log gönder")
        log_count = st.slider(
            "Kaç log üretilsin?",
            min_value=1,
            max_value=12,
            value=6,
            help=f"{len(EVENT_CATALOG)} farklı senaryo havuzundan rastgele seçilir.",
        )
        auto_analyze = st.checkbox(
            "Gönderdikten sonra otomatik analiz et",
            value=True,
            help="Loglar gider, hemen kurallar ve alarmlar oluşur.",
        )

        if st.button("📤 LOGLARI SİSTEME GÖNDER", type="primary", use_container_width=True):
            with st.spinner("Saldırı senaryoları üretiliyor ve gönderiliyor..."):
                try:
                    batch = generate_sample_events(log_count)
                    if auto_analyze:
                        result = Pipeline().run_full(batch, analyze=True)
                        st.session_state.last_lab_batch = {
                            "count": result.logs_ingested,
                            "rules": result.rules_created,
                            "alerts": result.alerts_created,
                            "soar": result.soar_responses,
                            "types": sorted({e["event"] for e in batch}),
                        }
                        msg = (
                            f"**{result.logs_ingested}** log · "
                            f"**{result.rules_created}** kural · **{result.alerts_created}** alarm"
                        )
                        if result.soar_responses:
                            msg += f" · **{result.soar_responses}** otomatik SOAR müdahalesi"
                        st.success(msg)
                    else:
                        count = Pipeline().ingest_logs(batch)
                        st.session_state.last_lab_batch = {
                            "count": count,
                            "rules": 0,
                            "alerts": 0,
                            "types": sorted({e["event"] for e in batch}),
                        }
                        st.success(f"**{count}** log gönderildi. Güvenlik Paneli'nde analiz et.")
                    st.rerun()
                except Exception:
                    logger.exception("Lab log send failed")
                    st.error("Log gönderilemedi.")

        if batch := st.session_state.get("last_lab_batch"):
            st.markdown("#### Son gönderim")
            types_tr = ", ".join(
                EVENT_TYPE_TR.get(t, t.replace("_", " ")) for t in batch.get("types", [])
            )
            st.caption(f"**{batch.get('count', 0)}** log · {types_tr}")
            if batch.get("rules"):
                extra = f"→ {batch['rules']} kural, {batch['alerts']} alarm"
                if batch.get("soar"):
                    extra += f", {batch['soar']} SOAR müdahalesi"
                st.caption(extra)

        st.markdown("---")
        st.caption("← Sol menüden **Güvenlik Paneli** sayfasına dönüp alarmları izle.")

    with col_info:
        st.markdown("### 📋 Senaryo kataloğu")
        st.caption(f"Toplam **{len(EVENT_CATALOG)}** farklı saldırı şablonu.")
        seen: set[str] = set()
        for item in EVENT_CATALOG:
            event = item["event"]
            if event in seen:
                continue
            seen.add(event)
            label = EVENT_TYPE_TR.get(event, event.replace("_", " "))
            technique = item.get("data", {}).get("technique", "—")
            st.markdown(f"- **{label}** · MITRE `{technique}`")

        with st.expander("Terminal komutu (alternatif)"):
            st.code(
                "python lab/poc_lab_simulator.py --count 6 --full",
                language="bash",
            )
            st.caption("Uygulama dışından da log gönderebilirsin — gerçek entegrasyon gibi.")
