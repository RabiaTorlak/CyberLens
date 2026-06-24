from datetime import date, datetime, time, timedelta, timezone
from typing import Any

from postgrest.exceptions import APIError
from supabase import Client, create_client

import config
from src.logging_config import get_logger

logger = get_logger("database")

_client: Client | None = None


def get_client() -> Client:
    global _client
    if _client is None:
        if not config.SUPABASE_URL or not config.SUPABASE_KEY:
            logger.error("Supabase credentials missing from environment")
            raise ValueError(
                "SUPABASE_URL and SUPABASE_KEY must be set in the .env file."
            )
        logger.info("Initializing Supabase client")
        _client = create_client(config.SUPABASE_URL, config.SUPABASE_KEY)
    return _client


def _day_bounds(report_date: date) -> tuple[str, str]:
    start = datetime.combine(report_date, time.min, tzinfo=timezone.utc)
    end = start + timedelta(days=1)
    return start.isoformat(), end.isoformat()


# --- Alerts ---


def insert_alert(data: dict[str, Any]) -> dict[str, Any]:
    try:
        response = get_client().table("alerts").insert(data).execute()
        logger.debug("Inserted alert: %s", data.get("title"))
        return response.data[0]
    except APIError:
        logger.exception("Failed to insert alert")
        raise


def get_alerts(limit: int = 100) -> list[dict[str, Any]]:
    try:
        response = (
            get_client()
            .table("alerts")
            .select("*")
            .order("created_at", desc=True)
            .limit(limit)
            .execute()
        )
        return response.data
    except APIError:
        logger.exception("Failed to fetch alerts (limit=%d)", limit)
        raise


def get_critical_alerts_for_day(report_date: date) -> list[dict[str, Any]]:
    start_iso, end_iso = _day_bounds(report_date)
    try:
        response = (
            get_client()
            .table("alerts")
            .select("*")
            .eq("severity", "critical")
            .gte("created_at", start_iso)
            .lt("created_at", end_iso)
            .order("created_at", desc=False)
            .execute()
        )
        logger.debug(
            "Fetched %d critical alerts for %s",
            len(response.data),
            report_date.isoformat(),
        )
        return response.data
    except APIError:
        logger.exception(
            "Failed to fetch critical alerts for %s", report_date.isoformat()
        )
        raise


def get_alert_by_log_id(log_id: str) -> dict[str, Any] | None:
    try:
        response = (
            get_client()
            .table("alerts")
            .select("*")
            .eq("matched_log_id", log_id)
            .limit(1)
            .execute()
        )
        return response.data[0] if response.data else None
    except APIError:
        logger.exception("Failed to fetch alert for log: %s", log_id)
        raise


def get_alert_by_id(alert_id: str) -> dict[str, Any] | None:
    try:
        response = (
            get_client()
            .table("alerts")
            .select("*")
            .eq("id", alert_id)
            .maybe_single()
            .execute()
        )
        return response.data
    except APIError:
        logger.exception("Failed to fetch alert by id: %s", alert_id)
        raise


def update_alert(alert_id: str, data: dict[str, Any]) -> dict[str, Any]:
    try:
        response = (
            get_client()
            .table("alerts")
            .update(data)
            .eq("id", alert_id)
            .execute()
        )
        logger.info("Updated alert: %s", alert_id)
        return response.data[0]
    except APIError:
        logger.exception("Failed to update alert: %s", alert_id)
        raise


def delete_alert(alert_id: str) -> None:
    try:
        get_client().table("alerts").delete().eq("id", alert_id).execute()
        logger.info("Deleted alert: %s", alert_id)
    except APIError:
        logger.exception("Failed to delete alert: %s", alert_id)
        raise


# --- Rules ---


def insert_rule(data: dict[str, Any]) -> dict[str, Any]:
    try:
        response = get_client().table("rules").insert(data).execute()
        logger.info("Inserted rule: %s", data.get("name"))
        return response.data[0]
    except APIError:
        logger.exception("Failed to insert rule")
        raise


def get_rules(limit: int = 100) -> list[dict[str, Any]]:
    try:
        response = (
            get_client()
            .table("rules")
            .select("*")
            .order("created_at", desc=True)
            .limit(limit)
            .execute()
        )
        return response.data
    except APIError:
        logger.exception("Failed to fetch rules (limit=%d)", limit)
        raise


def get_rule_by_id(rule_id: str) -> dict[str, Any] | None:
    try:
        response = (
            get_client()
            .table("rules")
            .select("*")
            .eq("id", rule_id)
            .maybe_single()
            .execute()
        )
        return response.data
    except APIError:
        logger.exception("Failed to fetch rule by id: %s", rule_id)
        raise


def update_rule(rule_id: str, data: dict[str, Any]) -> dict[str, Any]:
    try:
        response = (
            get_client()
            .table("rules")
            .update(data)
            .eq("id", rule_id)
            .execute()
        )
        logger.info("Updated rule: %s", rule_id)
        return response.data[0]
    except APIError:
        logger.exception("Failed to update rule: %s", rule_id)
        raise


def delete_rule(rule_id: str) -> None:
    try:
        get_client().table("rules").delete().eq("id", rule_id).execute()
        logger.info("Deleted rule: %s", rule_id)
    except APIError:
        logger.exception("Failed to delete rule: %s", rule_id)
        raise


def rule_exists_for_log(log_id: str) -> bool:
    try:
        response = (
            get_client()
            .table("rules")
            .select("id")
            .eq("metadata->>source_log_id", log_id)
            .limit(1)
            .execute()
        )
        return bool(response.data)
    except APIError:
        logger.exception("Failed to check rule for log: %s", log_id)
        raise


def get_rule_for_log(log_id: str) -> dict[str, Any] | None:
    try:
        response = (
            get_client()
            .table("rules")
            .select("*")
            .eq("metadata->>source_log_id", log_id)
            .order("created_at", desc=True)
            .limit(1)
            .execute()
        )
        return response.data[0] if response.data else None
    except APIError:
        logger.exception("Failed to fetch rule for log: %s", log_id)
        raise


# --- Logs ---


def insert_log(data: dict[str, Any]) -> dict[str, Any]:
    try:
        response = get_client().table("logs").insert(data).execute()
        logger.debug("Inserted log: %s", data.get("event_type"))
        return response.data[0]
    except APIError:
        logger.exception("Failed to insert log")
        raise


def insert_logs_batch(logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not logs:
        return []
    try:
        response = get_client().table("logs").insert(logs).execute()
        logger.info("Batch inserted %d log(s)", len(response.data))
        return response.data
    except APIError:
        logger.exception("Failed to batch insert %d log(s)", len(logs))
        raise


def get_logs(limit: int = 100) -> list[dict[str, Any]]:
    try:
        response = (
            get_client()
            .table("logs")
            .select("*")
            .order("created_at", desc=True)
            .limit(limit)
            .execute()
        )
        return response.data
    except APIError:
        logger.exception("Failed to fetch logs (limit=%d)", limit)
        raise


def get_log_by_id(log_id: str) -> dict[str, Any] | None:
    try:
        response = (
            get_client()
            .table("logs")
            .select("*")
            .eq("id", log_id)
            .maybe_single()
            .execute()
        )
        return response.data
    except APIError:
        logger.exception("Failed to fetch log by id: %s", log_id)
        raise


def update_log(log_id: str, data: dict[str, Any]) -> dict[str, Any]:
    try:
        response = (
            get_client()
            .table("logs")
            .update(data)
            .eq("id", log_id)
            .execute()
        )
        logger.info("Updated log: %s", log_id)
        return response.data[0]
    except APIError:
        logger.exception("Failed to update log: %s", log_id)
        raise


def delete_log(log_id: str) -> None:
    try:
        get_client().table("logs").delete().eq("id", log_id).execute()
        logger.info("Deleted log: %s", log_id)
    except APIError:
        logger.exception("Failed to delete log: %s", log_id)
        raise


def get_unprocessed_logs(limit: int = 50) -> list[dict[str, Any]]:
    try:
        response = (
            get_client()
            .table("logs")
            .select("*")
            .is_("analyzed_at", "null")
            .order("created_at", desc=False)
            .limit(limit)
            .execute()
        )
        return response.data
    except APIError:
        logger.exception("Failed to fetch unprocessed logs")
        raise


def mark_log_analyzed(log_id: str) -> None:
    timestamp = datetime.now(timezone.utc).isoformat()
    try:
        get_client().table("logs").update({"analyzed_at": timestamp}).eq("id", log_id).execute()
        logger.debug("Marked log analyzed: %s", log_id)
    except APIError:
        logger.exception("Failed to mark log analyzed: %s", log_id)
        raise
