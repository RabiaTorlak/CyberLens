"""Ortak test ayarları — testler ağ veya Supabase bağlantısı gerektirmez."""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Testler canlı API'lere gitmesin: anahtarları boş bırak (load_dotenv mevcut
# ortam değişkenlerini ezmez, yerel .env olsa bile bu değerler geçerli kalır).
for _key in ("VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY", "OTX_API_KEY", "CURSOR_API_KEY"):
    os.environ[_key] = ""
os.environ["AI_ANALYSIS_MODE"] = "heuristic"

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pytest  # noqa: E402

import src.threat_intel as threat_intel  # noqa: E402


@pytest.fixture(autouse=True)
def _clear_ti_cache():
    threat_intel.clear_cache()
    yield
    threat_intel.clear_cache()
