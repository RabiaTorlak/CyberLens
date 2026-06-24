"""Supabase Realtime alert listener (async) with polling fallback."""

from __future__ import annotations

import asyncio
import threading
from typing import Any, Callable

import config
from src.logging_config import get_logger

logger = get_logger("realtime")

_listener_started = False
_listener_mode = "polling"
_lock = threading.Lock()


def get_listener_mode() -> str:
    return _listener_mode


def _extract_record(payload: Any) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        return None

    data = payload.get("data") or {}
    record = (
        data.get("record")
        or payload.get("record")
        or payload.get("new")
    )
    if record:
        return record
    if payload.get("id") and payload.get("title"):
        return payload
    return None


async def _async_listen(on_alert: Callable[[dict[str, Any]], None]) -> None:
    global _listener_mode

    from supabase import acreate_client

    if not config.SUPABASE_URL or not config.SUPABASE_KEY:
        raise ValueError("Supabase credentials missing for Realtime listener")

    client = await acreate_client(config.SUPABASE_URL, config.SUPABASE_KEY)

    def handle(payload: Any) -> None:
        record = _extract_record(payload)
        if record:
            on_alert(record)

    channel = client.channel("dashboard-alerts")
    channel.on_postgres_changes(
        event="INSERT",
        schema="public",
        table="alerts",
        callback=handle,
    )
    await channel.subscribe()
    _listener_mode = "websocket"
    logger.info("Supabase Realtime WebSocket subscribed (alerts INSERT)")

    while True:
        await asyncio.sleep(60)


def _run_listener(on_alert: Callable[[dict[str, Any]], None]) -> None:
    global _listener_mode
    try:
        asyncio.run(_async_listen(on_alert))
    except Exception:
        logger.exception("Realtime WebSocket listener stopped; polling fallback active")
        _listener_mode = "polling"


def start_alert_listener(on_alert: Callable[[dict[str, Any]], None]) -> str:
    """Start background Realtime listener. Returns mode: websocket or polling."""
    global _listener_started

    with _lock:
        if _listener_started:
            return _listener_mode
        _listener_started = True

    if not config.SUPABASE_URL or not config.SUPABASE_KEY:
        logger.warning("Supabase not configured; alert polling only")
        return "polling"

    thread = threading.Thread(
        target=_run_listener,
        args=(on_alert,),
        daemon=True,
        name="supabase-realtime",
    )
    thread.start()

    # Brief wait for WebSocket handshake; keep polling until confirmed.
    import time

    for _ in range(10):
        if _listener_mode == "websocket":
            break
        time.sleep(0.3)

    if _listener_mode != "websocket":
        logger.info("Using polling fallback for alert updates (2s interval)")

    return _listener_mode
