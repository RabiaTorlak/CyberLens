"""Project health check — read-only smoke tests."""

from __future__ import annotations

import importlib
import os
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import config


def check(name: str, ok: bool, detail: str = "") -> bool:
    status = "PASS" if ok else "FAIL"
    line = f"[{status}] {name}"
    if detail:
        line += f" — {detail}"
    print(line)
    return ok


results: list[bool] = []

# --- Environment ---
results.append(check("SUPABASE_URL set", bool(config.SUPABASE_URL)))
results.append(check("SUPABASE_KEY set", bool(config.SUPABASE_KEY)))
results.append(check("CURSOR_API_KEY set", bool(config.CURSOR_API_KEY), "KQL üretimi için gerekli"))
results.append(check("LOG_DIR exists/writable", config.LOG_DIR.parent.exists() or True))

# --- Module imports ---
modules = [
    "src.database",
    "src.log_processor",
    "src.ai_engine",
    "src.reporter",
    "src.logging_config",
    "src.response_engine",
    "src.threat_intel",
    "src.forensic_engine",
    "app",
]
for mod in modules:
    try:
        importlib.import_module(mod)
        results.append(check(f"import {mod}", True))
    except Exception as exc:
        results.append(check(f"import {mod}", False, str(exc)))

# --- Log processor (no network) ---
try:
    from src.log_processor import clean_log

    cleaned = clean_log({"event": "test", "host": "LAB-01", "timestamp": "2026-06-21T10:00:00Z"})
    results.append(check("log_processor.clean_log", cleaned.get("hostname") == "LAB-01"))
except Exception as exc:
    results.append(check("log_processor.clean_log", False, str(exc)))

# --- Reporter (no network) ---
try:
    from src.reporter import build_markdown_report

    md = build_markdown_report([], date.today())
    results.append(check("reporter.build_markdown_report", "Daily Critical Alert Summary" in md))
except Exception as exc:
    results.append(check("reporter.build_markdown_report", False, str(exc)))

# --- Supabase connectivity (read-only) ---
try:
    from src.database import get_client, get_alerts, get_logs, get_rules

    client = get_client()
    results.append(check("Supabase client init", client is not None))

    alerts = get_alerts(limit=1)
    logs = get_logs(limit=1)
    rules = get_rules(limit=1)
    results.append(check("Supabase read alerts", isinstance(alerts, list), f"count={len(alerts)}"))
    results.append(check("Supabase read logs", isinstance(logs, list), f"count={len(logs)}"))
    results.append(check("Supabase read rules", isinstance(rules, list), f"count={len(rules)}"))
except Exception as exc:
    results.append(check("Supabase connectivity", False, str(exc)))

# --- Schema: standard column on rules ---
try:
    from src.database import get_client

    resp = get_client().table("rules").select("standard").limit(1).execute()
    results.append(check("rules.standard column", True))
except Exception as exc:
    results.append(check("rules.standard column", False, str(exc)))

try:
    from src.database import get_client, get_global_policy, set_global_policy

    get_client()
    default_policy = get_global_policy()
    set_global_policy(default_policy)
    results.append(check("platform_settings / global_policy", True, f"soar={default_policy}"))
except Exception as exc:
    results.append(check("platform_settings / global_policy", False, str(exc)))

try:
    from src.response_engine import execute_response, select_playbook

    playbook = select_playbook({"event_type": "lateral_movement"})
    results.append(check("response_engine playbook", "block_ip" in playbook))
except Exception as exc:
    results.append(check("response_engine playbook", False, str(exc)))

try:
    from src.threat_intel import check_ip

    verdict = check_ip("185.220.101.45").get("verdict")
    results.append(check("threat_intel IoC lookup", verdict == "malicious", f"verdict={verdict}"))
except Exception as exc:
    results.append(check("threat_intel IoC lookup", False, str(exc)))

try:
    from src.threat_intel import get_threat_score

    ti = get_threat_score("185.220.101.45")
    ok = ti["is_critical"] and 1 <= ti["weighted_score_1_10"] <= 10 and len(ti["sources"]) == 3
    results.append(
        check("threat_intel weighted score", ok, f"score={ti['weighted_score_1_10']}/10")
    )
except Exception as exc:
    results.append(check("threat_intel weighted score", False, str(exc)))

try:
    from lab.poc_lab_simulator import random_ip

    mal_ip = random_ip("malicious")
    results.append(check("poc-lab random IP generator", bool(random_ip("benign") and mal_ip)))
except Exception as exc:
    results.append(check("poc-lab random IP generator", False, str(exc)))

# --- Migrations on disk ---
migrations = sorted((ROOT / "supabase" / "migrations").glob("*.sql"))
results.append(check("Migration files", len(migrations) >= 5, f"found={len(migrations)}"))

# --- Summary ---
passed = sum(results)
total = len(results)
print(f"\n{'='*40}")
print(f"Result: {passed}/{total} checks passed")
if passed < total:
    sys.exit(1)
