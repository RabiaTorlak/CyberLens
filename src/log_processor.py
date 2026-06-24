"""Batch log processing with cleaning and buffered Supabase writes."""

from __future__ import annotations

import json
import re
import threading
import time
from datetime import datetime, timezone
from typing import Any

from src.database import insert_logs_batch
from src.logging_config import get_logger

logger = get_logger("log_processor")

BATCH_INTERVAL_SECONDS = 5
BATCH_SIZE_THRESHOLD = 10

_RESERVED_FIELDS = frozenset(
    {"source", "log_source", "event_type", "event", "type", "hostname", "host", "computer", "username", "user", "account", "event_time", "timestamp", "@timestamp", "raw_data", "data"}
)

_NULL_BYTE_PATTERN = re.compile(r"\x00")


def clean_string(value: Any, max_length: int = 512) -> str | None:
    if value is None:
        return None

    text = _NULL_BYTE_PATTERN.sub("", str(value)).strip()
    if not text:
        return None

    return text[:max_length]


def normalize_event_time(value: Any) -> str | None:
    if value is None:
        return None

    if isinstance(value, (int, float)):
        timestamp = value / 1000 if value > 1_000_000_000_000 else value
        return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()

    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat()

    text = clean_string(value, max_length=64)
    if not text:
        return None

    normalized = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return text

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat()


def _deep_clean_value(value: Any) -> Any:
    if isinstance(value, str):
        return _NULL_BYTE_PATTERN.sub("", value).strip()
    if isinstance(value, dict):
        return {clean_string(k, max_length=128) or str(k): _deep_clean_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_deep_clean_value(item) for item in value]
    return value


def clean_raw_data(data: Any) -> dict[str, Any]:
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except json.JSONDecodeError:
            return {"message": clean_string(data, max_length=4096) or ""}

    if not isinstance(data, dict):
        return {"value": _deep_clean_value(data)}

    cleaned = _deep_clean_value(data)
    return cleaned if isinstance(cleaned, dict) else {"value": cleaned}


def clean_log(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize poc-lab log payloads into the logs table schema."""
    if not isinstance(raw, dict):
        logger.error("Invalid log payload type: %s", type(raw).__name__)
        raise TypeError("Log payload must be a dictionary.")

    source = clean_string(
        raw.get("source") or raw.get("log_source") or "poc-lab"
    )
    event_type = clean_string(
        raw.get("event_type") or raw.get("event") or raw.get("type")
    )
    hostname = clean_string(
        raw.get("hostname") or raw.get("host") or raw.get("computer")
    )
    username = clean_string(
        raw.get("username") or raw.get("user") or raw.get("account")
    )
    event_time = normalize_event_time(
        raw.get("event_time") or raw.get("timestamp") or raw.get("@timestamp")
    )

    if raw.get("raw_data") is not None:
        raw_data = clean_raw_data(raw["raw_data"])
    elif raw.get("data") is not None:
        raw_data = clean_raw_data(raw["data"])
    else:
        raw_data = clean_raw_data(
            {key: value for key, value in raw.items() if key not in _RESERVED_FIELDS}
        )

    cleaned: dict[str, Any] = {"raw_data": raw_data}
    if source:
        cleaned["source"] = source
    if event_type:
        cleaned["event_type"] = event_type
    if hostname:
        cleaned["hostname"] = hostname
    if username:
        cleaned["username"] = username
    if event_time:
        cleaned["event_time"] = event_time

    return cleaned


class LogBuffer:
    """Buffers cleaned logs and flushes on interval or batch size threshold."""

    def __init__(
        self,
        interval_seconds: float = BATCH_INTERVAL_SECONDS,
        batch_size: int = BATCH_SIZE_THRESHOLD,
    ) -> None:
        self.interval_seconds = interval_seconds
        self.batch_size = batch_size
        self._buffer: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._running = False
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._flush_loop, daemon=True)
        self._thread.start()
        logger.info(
            "Log buffer started (interval=%ss, batch_size=%d)",
            self.interval_seconds,
            self.batch_size,
        )

    def stop(self) -> int:
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=self.interval_seconds + 1)
        flushed = self.flush()
        logger.info("Log buffer stopped; final flush=%d", flushed)
        return flushed

    def add(self, log: dict[str, Any]) -> None:
        should_flush = False
        with self._lock:
            self._buffer.append(log)
            should_flush = len(self._buffer) >= self.batch_size

        if should_flush:
            self.flush()

    def flush(self) -> int:
        with self._lock:
            if not self._buffer:
                return 0
            batch = self._buffer[:]
            self._buffer.clear()

        try:
            insert_logs_batch(batch)
            logger.info("Flushed %d log(s) to Supabase", len(batch))
            return len(batch)
        except Exception:
            with self._lock:
                self._buffer = batch + self._buffer
            logger.exception("Buffer flush failed; %d log(s) restored to queue", len(batch))
            raise

    def pending_count(self) -> int:
        with self._lock:
            return len(self._buffer)

    def _flush_loop(self) -> None:
        while self._running:
            time.sleep(self.interval_seconds)
            self.flush()


class LogProcessor:
    """Processes poc-lab logs with cleaning and buffered persistence."""

    def __init__(
        self,
        interval_seconds: float = BATCH_INTERVAL_SECONDS,
        batch_size: int = BATCH_SIZE_THRESHOLD,
        auto_start: bool = True,
    ) -> None:
        self.buffer = LogBuffer(
            interval_seconds=interval_seconds,
            batch_size=batch_size,
        )
        if auto_start:
            self.buffer.start()

    def process(self, raw_log: dict[str, Any]) -> dict[str, Any]:
        cleaned = clean_log(raw_log)
        self.buffer.add(cleaned)
        return cleaned

    def process_many(self, raw_logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
        cleaned_logs = [clean_log(raw_log) for raw_log in raw_logs]
        for cleaned in cleaned_logs:
            self.buffer.add(cleaned)
        return cleaned_logs

    def flush(self) -> int:
        return self.buffer.flush()

    def shutdown(self) -> int:
        return self.buffer.stop()

    @property
    def pending_count(self) -> int:
        return self.buffer.pending_count()


_processor: LogProcessor | None = None


def get_processor() -> LogProcessor:
    global _processor
    if _processor is None:
        _processor = LogProcessor()
    return _processor
