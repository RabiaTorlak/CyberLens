from src import response_engine as soar


def test_playbook_selection_by_event_type():
    assert soar.select_playbook({"event_type": "lateral_movement"}) == [
        "block_ip",
        "isolate_host",
        "notify_soc",
    ]
    assert soar.select_playbook({"event_type": "unknown_thing"}) == soar.DEFAULT_PLAYBOOK


def test_block_ip_uses_ip_from_log():
    log = {"event_type": "data_exfiltration", "raw_data": {"destination": "45.155.205.10"}}
    result = soar.execute_response({"id": "a1"}, log)
    assert result["action_details"][0] == "IP engellendi: 45.155.205.10"


def test_block_ip_is_skipped_when_log_has_no_ip():
    # Eskiden logda IP yoksa sabit bir IP "engellendi" olarak raporlanıyordu.
    log = {"event_type": "lateral_movement", "hostname": "LAB-WS01", "raw_data": {"tool": "psexec"}}
    result = soar.execute_response({"id": "a2"}, log)
    assert "atlandı" in result["action_details"][0]
    assert "185.220.101.45" not in " ".join(result["action_details"])


def test_domain_destination_is_not_treated_as_ip():
    log = {"event_type": "command_and_control", "raw_data": {"c2_host": "beacon.evil.net"}}
    assert soar._extract_ip(log) is None


def test_quarantine_skipped_without_process_info():
    log = {"event_type": "powershell_execution", "raw_data": "not-a-dict"}
    details = soar.execute_response({"id": "a3"}, log)["action_details"]
    assert "atlandı" in details[0]


def test_apply_soar_disabled_returns_alert_unchanged(monkeypatch):
    monkeypatch.setattr(soar, "get_global_policy", lambda: False)
    alert = {"id": "a4", "status": "open"}
    assert soar.apply_soar_if_enabled(alert, {"event_type": "phishing"}) is alert


def test_apply_soar_enabled_updates_alert(monkeypatch):
    captured = {}

    def fake_update(alert_id, data):
        captured["id"] = alert_id
        return {"id": alert_id, **data}

    monkeypatch.setattr(soar, "get_global_policy", lambda: True)
    monkeypatch.setattr(soar, "update_alert", fake_update)
    alert = {"id": "a5", "description": "x", "metadata": {}}
    updated = soar.apply_soar_if_enabled(alert, {"event_type": "phishing", "raw_data": {}})
    assert captured["id"] == "a5"
    assert updated["status"] == "investigating"
    assert updated["metadata"]["soar"]["playbook"] == ["block_ip", "notify_soc"]
