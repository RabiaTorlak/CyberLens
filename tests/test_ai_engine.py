import pytest

from src import ai_engine


def test_heuristic_detects_credential_access_with_mitre_and_kql():
    log = {
        "id": "log-1",
        "event_type": "credential_access",
        "hostname": "LAB-DC01",
        "username": "admin",
        "raw_data": {"technique": "T1003", "target": "lsass.exe"},
    }
    analysis = ai_engine.analyze_log_heuristic(log)
    assert analysis.threat_detected is True
    assert analysis.severity == "high"
    assert "T1003" in analysis.mitre_techniques
    assert "MITRE:T1003" in analysis.standard
    assert analysis.kql_query.startswith("SecurityEvent")
    assert 'Computer has "LAB-DC01"' in analysis.kql_query


def test_heuristic_ignores_benign_test_event():
    analysis = ai_engine.analyze_log_heuristic({"event_type": "test", "raw_data": {}})
    assert analysis.threat_detected is False
    assert analysis.kql_query == ""


def test_heuristic_kql_escapes_quotes():
    log = {
        "event_type": "lateral_movement",
        "hostname": 'evil" or 1==1 //',
        "username": "bob",
        "raw_data": {},
    }
    kql = ai_engine.analyze_log_heuristic(log).kql_query
    assert 'has "evil\\" or 1==1 //"' in kql


def test_parse_llm_response_handles_markdown_fence():
    text = 'Here you go:\n```json\n{"threat_detected": true, "severity": "HIGH"}\n```'
    payload = ai_engine.parse_llm_response(text)
    assert payload["threat_detected"] is True


def test_parse_llm_response_without_json_raises():
    with pytest.raises(ValueError):
        ai_engine.parse_llm_response("no json at all")


def test_to_threat_analysis_normalizes_unknown_severity():
    analysis = ai_engine.to_threat_analysis(
        {"threat_detected": True, "severity": "apocalyptic", "mitre_techniques": ["T1059", " "]}
    )
    assert analysis.severity == "medium"
    assert analysis.mitre_techniques == ["T1059"]
    assert analysis.standard == "MITRE:T1059"


def test_resolve_mode_falls_back_to_heuristic_without_key(monkeypatch):
    monkeypatch.setattr(ai_engine.config, "AI_ANALYSIS_MODE", "cursor")
    monkeypatch.setattr(ai_engine.config, "CURSOR_API_KEY", "")
    assert ai_engine.resolve_analysis_mode() == "heuristic"
