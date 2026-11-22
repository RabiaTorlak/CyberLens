"""SOAR otomatik müdahale motoru — tehdit tespitinde playbook aksiyonları."""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Any

from src.database import get_global_policy, update_alert
from src.logging_config import get_logger

logger = get_logger("response_engine")

ACTION_LABELS_TR: dict[str, str] = {
    "block_ip": "IP engellendi",
    "isolate_host": "Host izole edildi",
    "disable_user": "Kullanıcı devre dışı bırakıldı",
    "quarantine_process": "Process karantinaya alındı",
    "force_password_reset": "Zorunlu parola sıfırlama tetiklendi",
    "notify_soc": "SOC ekibine bildirim gönderildi",
}

PLAYBOOK_BY_EVENT: dict[str, list[str]] = {
    "credential_access": ["disable_user", "force_password_reset", "isolate_host"],
    "lateral_movement": ["block_ip", "isolate_host", "notify_soc"],
    "powershell_execution": ["quarantine_process", "isolate_host"],
    "data_exfiltration": ["block_ip", "isolate_host", "notify_soc"],
    "malware_download": ["block_ip", "quarantine_process", "isolate_host"],
    "command_and_control": ["block_ip", "isolate_host"],
    "suspicious_execution": ["quarantine_process", "notify_soc"],
    "privilege_escalation": ["disable_user", "isolate_host"],
    "phishing": ["block_ip", "notify_soc"],
}

DEFAULT_PLAYBOOK = ["notify_soc", "isolate_host"]


def _raw_dict(log: dict[str, Any]) -> dict[str, Any]:
    raw = log.get("raw_data") or {}
    return raw if isinstance(raw, dict) else {}


def _extract_ip(log: dict[str, Any]) -> str | None:
    """Logdaki ilk geçerli IP adresini döndür; yoksa None (sahte IP üretilmez)."""
    raw = _raw_dict(log)
    for key in ("destination", "c2_host", "remote_ip", "src_ip", "ip"):
        value = raw.get(key)
        if not value:
            continue
        candidate = str(value).split("/")[0].split(":")[0].strip()
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        return candidate
    return None


def _build_action_detail(action: str, log: dict[str, Any]) -> str:
    hostname = log.get("hostname") or "unknown-host"
    username = log.get("username") or "unknown-user"

    if action == "block_ip":
        ip = _extract_ip(log)
        if ip is None:
            return "IP engelleme atlandı: logda geçerli IP adresi yok"
        return f"{ACTION_LABELS_TR[action]}: {ip}"
    if action == "isolate_host":
        return f"{ACTION_LABELS_TR[action]}: {hostname}"
    if action == "disable_user":
        return f"{ACTION_LABELS_TR[action]}: {username}"
    if action == "quarantine_process":
        raw = _raw_dict(log)
        process = raw.get("process") or raw.get("command") or raw.get("tool")
        if not process:
            return "Process karantinası atlandı: logda process bilgisi yok"
        return f"{ACTION_LABELS_TR[action]}: {process}"
    if action == "force_password_reset":
        return f"{ACTION_LABELS_TR[action]}: {username}"
    return ACTION_LABELS_TR.get(action, action)


def select_playbook(log: dict[str, Any]) -> list[str]:
    event = str(log.get("event_type") or "").lower()
    return PLAYBOOK_BY_EVENT.get(event, DEFAULT_PLAYBOOK)


def execute_response(
    alert: dict[str, Any],
    log: dict[str, Any],
    rule: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Playbook aksiyonlarını simüle et ve özet döndür."""
    actions = select_playbook(log)
    details = [_build_action_detail(action, log) for action in actions]
    primary = details[0] if details else "Otomatik müdahale uygulandı"

    logger.info(
        "SOAR response for alert %s: %s",
        alert.get("id"),
        "; ".join(details),
    )

    return {
        "auto_response": True,
        "playbook": actions,
        "action_summary": primary,
        "action_details": details,
        "rule_name": (rule or {}).get("name"),
        "event_type": log.get("event_type"),
        "hostname": log.get("hostname"),
        "executed_at": datetime.now(timezone.utc).isoformat(),
        "engine": "response_engine",
    }


def apply_soar_if_enabled(
    alert: dict[str, Any],
    log: dict[str, Any],
    rule: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    global_policy açıksa otomatik müdahale uygula ve alarm metadata'sını güncelle.
    Kapalıysa alert'i olduğu gibi döndür.
    """
    if not get_global_policy():
        return alert

    soar_result = execute_response(alert, log, rule)
    metadata = dict(alert.get("metadata") or {})
    metadata["soar"] = soar_result
    metadata["global_policy_active"] = True

    updated = update_alert(
        str(alert["id"]),
        {
            "metadata": metadata,
            "status": "investigating",
            "description": (
                f"{alert.get('description', '')}\n\n"
                f"[SOAR] Otomatik müdahale: {soar_result['action_summary']}"
            ).strip(),
        },
    )
    logger.info("SOAR auto-response applied to alert %s", alert.get("id"))
    return updated
