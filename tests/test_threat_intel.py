from src import threat_intel as ti


def test_internal_ip_is_not_scored():
    result = ti.get_threat_score("192.168.1.10")
    assert result["verdict"] == "internal"
    assert result["is_critical"] is False
    assert result["sources"] == []


def test_known_bad_ip_is_critical_offline():
    result = ti.get_threat_score("185.220.101.45")
    assert result["is_critical"] is True
    assert result["verdict"] == "malicious"
    assert result["weighted_score_1_10"] == 10.0
    assert {s["source"] for s in result["sources"]} == {"virustotal", "abuseipdb", "otx"}
    assert all(s["available"] is False for s in result["sources"])


def test_unknown_public_ip_is_clean_offline():
    result = ti.get_threat_score("8.8.8.8")
    assert result["is_critical"] is False
    assert result["verdict"] == "clean"


def test_normalization_bounds():
    assert ti._norm_1_10(0) == 1.0
    assert ti._norm_1_10(100) == 10.0
    assert ti._norm_1_10(250) == 10.0
    assert ti._norm_1_10(-5) == 1.0


def test_extract_iocs_splits_ips_domains_and_files():
    raw = {
        "destination": "185.220.101.45",
        "url": "http://malicious.example/payload.exe",
        "attachment": "invoice.zip",
    }
    iocs = ti.extract_iocs(raw)
    assert iocs["ips"] == ["185.220.101.45"]
    assert "malicious.example" in iocs["domains"]
    assert "invoice.zip" in iocs["files"]


def test_extract_iocs_ignores_non_dict():
    assert ti.extract_iocs("not a dict") == {"ips": [], "domains": [], "files": []}


def test_assess_log_flags_malicious_destination():
    log = {"raw_data": {"destination": "185.220.101.45", "bytes_out": 1024}}
    result = ti.assess_log(log)
    assert result["is_malicious"] is True
    assert result["primary_ioc"] == "185.220.101.45"


def test_assess_log_without_iocs():
    result = ti.assess_log({"raw_data": {"note": "nothing here"}})
    assert result["verdict"] == "unknown"
    assert result["indicators"] == []


def test_check_file_matches_tool_signature():
    assert ti.check_file("Invoke-Mimikatz.ps1")["verdict"] == "malicious"
    assert ti.check_file("notepad.exe")["verdict"] == "clean"
