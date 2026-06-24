"""Alert creation from detection rules and analysis results."""

from __future__ import annotations

from typing import Any

from src.database import get_alert_by_log_id, insert_alert
from src.logging_config import get_logger

logger = get_logger("alert_engine")


def build_alert_payload(
    rule: dict[str, Any],
    log_id: str | None,
    *,
    analysis_engine: str = "cursor",
) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "standard": rule.get("standard"),
        "analysis_engine": analysis_engine,
    }
    if log_id:
        metadata["source_log_id"] = log_id

    rule_metadata = rule.get("metadata") or {}
    if isinstance(rule_metadata, dict):
        metadata.update(
            {
                "nist_controls": rule_metadata.get("nist_controls", []),
                "mitre_techniques": rule_metadata.get("mitre_techniques", []),
            }
        )

    return {
        "rule_id": rule.get("id"),
        "matched_log_id": log_id,
        "title": rule.get("name", "Detection Alert"),
        "description": rule.get("description") or "Automated detection triggered by poc-lab telemetry.",
        "severity": rule.get("severity", "medium"),
        "status": "open",
        "metadata": metadata,
    }


def create_alert_for_rule(
    rule: dict[str, Any],
    log_id: str | None,
    *,
    analysis_engine: str = "cursor",
) -> dict[str, Any]:
    if log_id:
        existing = get_alert_by_log_id(log_id)
        if existing:
            logger.info("Alert already exists for log %s: %s", log_id, existing.get("id"))
            return existing

    payload = build_alert_payload(rule, log_id, analysis_engine=analysis_engine)
    alert = insert_alert(payload)
    logger.info("Alert created: %s (severity=%s)", alert.get("title"), alert.get("severity"))
    return alert
