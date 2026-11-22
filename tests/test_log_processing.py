import pytest

from src.alert_engine import build_alert_payload
from src.log_processor import clean_log, normalize_event_time


def test_clean_log_maps_aliases_and_strips_null_bytes():
    cleaned = clean_log(
        {
            "event": "credential_access",
            "host": "LAB-DC01\x00",
            "user": "  admin ",
            "timestamp": "2026-01-01T10:00:00Z",
            "data": {"technique": "T1003"},
        }
    )
    assert cleaned["event_type"] == "credential_access"
    assert cleaned["hostname"] == "LAB-DC01"
    assert cleaned["username"] == "admin"
    assert cleaned["source"] == "poc-lab"
    assert cleaned["event_time"] == "2026-01-01T10:00:00+00:00"
    assert cleaned["raw_data"] == {"technique": "T1003"}


def test_clean_log_rejects_non_dict():
    with pytest.raises(TypeError):
        clean_log(["not", "a", "dict"])


def test_normalize_event_time_epoch_millis():
    assert normalize_event_time(1_700_000_000_000).startswith("2023-11-14")


def test_alert_payload_carries_mitre_metadata():
    rule = {
        "id": "r1",
        "name": "Suspicious Credential Access",
        "severity": "high",
        "standard": "MITRE:T1003",
        "metadata": {"mitre_techniques": ["T1003"], "nist_controls": ["DE.AE"]},
    }
    payload = build_alert_payload(rule, "log-1", analysis_engine="heuristic")
    assert payload["status"] == "open"
    assert payload["matched_log_id"] == "log-1"
    assert payload["metadata"]["mitre_techniques"] == ["T1003"]
    assert payload["metadata"]["analysis_engine"] == "heuristic"
