"""Forensic Timeline — bir alarmın saldırganına ait olayları kronolojik dizer."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from src.database import get_alert_by_id, get_log_by_id, get_logs_by_actor
from src.logging_config import get_logger

logger = get_logger("forensic_engine")

EVENT_LABEL_TR: dict[str, str] = {
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
    "login": "Oturum açma",
    "file_access": "Dosya erişimi",
    "network": "Ağ hareketi",
    "test": "Test olayı",
    "info": "Bilgi",
    "unknown": "Bilinmeyen olay",
}

# Kategori — kabaca saldırı zincirindeki aşama (renk/ikon için)
EVENT_CATEGORY: dict[str, str] = {
    "login": "access",
    "credential_access": "access",
    "phishing": "access",
    "reconnaissance": "recon",
    "powershell_execution": "execution",
    "suspicious_execution": "execution",
    "execution": "execution",
    "privilege_escalation": "escalation",
    "persistence": "persistence",
    "defense_evasion": "evasion",
    "lateral_movement": "movement",
    "file_access": "collection",
    "data_exfiltration": "exfil",
    "exfil": "exfil",
    "malware_download": "delivery",
    "command_and_control": "c2",
    "network": "network",
}

_SUMMARY_KEYS = (
    "command",
    "command_line",
    "tool",
    "process",
    "target",
    "target_host",
    "destination",
    "c2_host",
    "url",
    "method",
    "channel",
    "registry_key",
    "subject",
    "attachment",
    "ports_scanned",
    "action",
    "details",
)


def event_label(event_type: str | None) -> str:
    key = str(event_type or "unknown").lower()
    return EVENT_LABEL_TR.get(key, str(event_type or "Bilinmeyen olay").replace("_", " "))


def event_category(event_type: str | None) -> str:
    return EVENT_CATEGORY.get(str(event_type or "").lower(), "network")


def _parse_time(value: Any) -> datetime:
    if not value:
        return datetime.min.replace(tzinfo=timezone.utc)
    text = str(value).replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _summarize_raw(raw: Any) -> tuple[str, str]:
    """raw_data'dan kısa özet ve (varsa) MITRE tekniği çıkar."""
    if not isinstance(raw, dict):
        return (str(raw) if raw else "—"), ""
    technique = str(raw.get("technique") or "")
    parts: list[str] = []
    for key in _SUMMARY_KEYS:
        if key in raw and raw[key] not in (None, "", []):
            parts.append(f"{key}={raw[key]}")
        if len(parts) >= 3:
            break
    summary = " · ".join(parts) if parts else "—"
    return summary, technique


def _identity_from_log(log: dict[str, Any]) -> dict[str, str | None]:
    return {
        "hostname": log.get("hostname"),
        "username": log.get("username"),
        "source": log.get("source"),
    }


def build_timeline_event(log: dict[str, Any], *, pivot_id: str | None = None) -> dict[str, Any]:
    raw = log.get("raw_data") or {}
    summary, technique = _summarize_raw(raw)
    when = log.get("event_time") or log.get("created_at")
    dt = _parse_time(when)
    event_type = log.get("event_type") or "unknown"

    return {
        "log_id": str(log.get("id", "")),
        "timestamp": when,
        "datetime": dt,
        "time_display": dt.strftime("%H:%M:%S") if dt.year > 1 else "—",
        "date_display": dt.strftime("%Y-%m-%d") if dt.year > 1 else "—",
        "event_type": event_type,
        "event_label": event_label(event_type),
        "category": event_category(event_type),
        "hostname": log.get("hostname") or "bilinmeyen-host",
        "username": log.get("username") or "bilinmeyen-kullanıcı",
        "source": log.get("source") or "—",
        "summary": summary,
        "technique": technique,
        "is_pivot": bool(pivot_id) and str(log.get("id", "")) == str(pivot_id),
    }


def build_timeline_for_alert(alert_id: str) -> dict[str, Any]:
    """
    Alarmı al → eşleşen logdan saldırgan kimliğini çıkar →
    aynı host/kullanıcıya ait tüm logları kronolojik diz.
    """
    alert = get_alert_by_id(alert_id)
    if not alert:
        logger.warning("Timeline: alert not found %s", alert_id)
        return {"alert": None, "identity": {}, "events": []}

    pivot_log = None
    matched_log_id = alert.get("matched_log_id")
    if matched_log_id:
        pivot_log = get_log_by_id(str(matched_log_id))

    if pivot_log is None:
        identity = {"hostname": None, "username": None, "source": None}
    else:
        identity = _identity_from_log(pivot_log)

    related_logs: list[dict[str, Any]] = []
    if identity.get("hostname") or identity.get("username"):
        related_logs = get_logs_by_actor(
            hostname=identity.get("hostname"),
            username=identity.get("username"),
            limit=300,
        )

    # pivot log listede yoksa ekle
    if pivot_log and not any(str(l.get("id")) == str(pivot_log.get("id")) for l in related_logs):
        related_logs.append(pivot_log)

    events = [
        build_timeline_event(log, pivot_id=str(matched_log_id or ""))
        for log in related_logs
    ]
    events.sort(key=lambda e: e["datetime"])

    return {
        "alert": alert,
        "identity": identity,
        "events": events,
        "event_count": len(events),
    }
