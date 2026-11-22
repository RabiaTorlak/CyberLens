"""CyberLens — çok sayfalı SOC / tespit mühendisliği platformu."""

from __future__ import annotations

import streamlit as st

from src.ui.lab_page import render_lab_page
from src.ui.soc_page import render_soc_page

st.set_page_config(
    page_title="CyberLens",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

nav = st.navigation(
    [
        st.Page(render_soc_page, title="Güvenlik Paneli", icon="🛡️", default=True),
        st.Page(render_lab_page, title="Saldırı Lab", icon="🧪"),
    ]
)
nav.run()
