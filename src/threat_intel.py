"""Threat Intelligence — çoklu kaynak IoC risk değerlendirme.

VirusTotal, AbuseIPDB ve AlienVault OTX API'lerini destekler. Anahtar varsa
canlı sorgu yapar; yoksa yerleşik bilinen-zararlı listesi + IP blok sezgisiyle
offline çalışır. Her kaynak 1-10 arası normalize edilip ağırlıklı ortalama ile
tek bir 'Weighted Risk Score' üretilir.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

import config
from src.database import get_log_by_id
from src.logging_config import get_logger

logger = get_logger("threat_intel")

# --- Yerleşik istihbarat (offline fallback / demo) ---

KNOWN_BAD_IPS: dict[str, int] = {
    "185.220.101.45": 100,   # Tor exit node (poc-lab exfil hedefi)
    "185.220.100.255": 95,
    "45.155.205.233": 90,
    "194.165.16.76": 88,
}

# Offline demo: bu /24 ön ekleri "bilinen zararlı blok" sayılır (Tor/bulletproof).
MALICIOUS_IP_PREFIXES: dict[str, int] = {
    "185.220.101": 95,
    "185.220.100": 92,
    "45.155.205": 90,
    "194.165.16": 88,
    "193.106.191": 85,
    "91.219.236": 83,
}

KNOWN_BAD_DOMAINS: dict[str, int] = {
    "beacon.evil.net": 96,
    "malicious.example": 92,
    "c2.darknet.io": 90,
}

SUSPICIOUS_FILES: dict[str, int] = {
    "mimikatz": 95,
    "lsass.exe": 70,
    "payload.exe": 88,
    "invoice.zip": 65,
    "cobaltstrike": 97,
}

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")

_VERDICT_TR = {
    "malicious": "Bilinen Zararlı",
    "suspicious": "Şüpheli",
    "clean": "Temiz",
    "internal": "İç Ağ",
    "unknown": "Bilinmiyor",
}

# alarm id -> değerlendirme (tekrar sorguyu önler)
_ASSESS_CACHE: dict[str, dict[str, Any]] = {}
# ip -> değerlendirme
_IP_CACHE: dict[str, dict[str, Any]] = {}


def verdict_label(verdict: str) -> str:
    return _VERDICT_TR.get(verdict, verdict)


def _is_internal_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _empty_result() -> dict[str, Any]:
    return {
        "risk_score": 0,
        "verdict": "unknown",
        "is_malicious": False,
        "note": "Değerlendirilecek IoC bulunamadı.",
        "indicators": [],
        "source": "none",
    }


def _prefix24(ip: str) -> str:
    parts = ip.split(".")
    return ".".join(parts[:3]) if len(parts) == 4 else ip


def _norm_1_10(value_0_100: float) -> float:
    """0-100 aralığını 1-10'a normalize et."""
    value = max(0.0, min(100.0, float(value_0_100)))
    return round(1 + (value / 100.0) * 9, 1)


# --- Kaynak sorgulayıcıları: her biri {score_0_100, normalized_1_10, raw, available} döndürür ---


def _source_result(
    name: str,
    score_0_100: float,
    *,
    available: bool,
    malicious: bool,
    detail: str,
) -> dict[str, Any]:
    return {
        "source": name,
        "available": available,
        "score_0_100": round(float(score_0_100), 1),
        "normalized": _norm_1_10(score_0_100),
        "malicious": malicious,
        "detail": detail,
    }


def _offline_score(ip: str) -> float:
    """Anahtar yokken IP için sentetik itibar skoru (0-100)."""
    if ip in KNOWN_BAD_IPS:
        return float(KNOWN_BAD_IPS[ip])
    prefix = _prefix24(ip)
    if prefix in MALICIOUS_IP_PREFIXES:
        return float(MALICIOUS_IP_PREFIXES[prefix])
    return 5.0


def query_virustotal(ip: str) -> dict[str, Any]:
    if config.VIRUSTOTAL_API_KEY:
        try:
            import httpx

            resp = httpx.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": config.VIRUSTOTAL_API_KEY},
                timeout=4.0,
            )
            resp.raise_for_status()
            stats = (
                resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            )
            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            total = sum(int(v) for v in stats.values()) or 1
            score = (malicious + 0.5 * suspicious) / total * 100
            return _source_result(
                "virustotal",
                score,
                available=True,
                malicious=malicious > 0,
                detail=f"{malicious}/{total} motor zararlı dedi",
            )
        except Exception as exc:
            logger.warning("VirusTotal query failed for %s: %s", ip, exc)

    score = _offline_score(ip)
    return _source_result(
        "virustotal",
        score,
        available=False,
        malicious=score >= 75,
        detail="offline tahmin (anahtar yok)",
    )


def query_abuseipdb(ip: str) -> dict[str, Any]:
    if config.ABUSEIPDB_API_KEY:
        try:
            import httpx

            resp = httpx.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": config.ABUSEIPDB_API_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
                timeout=4.0,
            )
            resp.raise_for_status()
            data = resp.json().get("data", {})
            score = int(data.get("abuseConfidenceScore", 0))
            reports = data.get("totalReports", 0)
            country = data.get("countryCode") or "?"
            return _source_result(
                "abuseipdb",
                score,
                available=True,
                malicious=score >= 50,
                detail=f"%{score} güven · {reports} rapor · {country}",
            )
        except Exception as exc:
            logger.warning("AbuseIPDB query failed for %s: %s", ip, exc)

    score = _offline_score(ip)
    return _source_result(
        "abuseipdb",
        score,
        available=False,
        malicious=score >= 50,
        detail="offline tahmin (anahtar yok)",
    )


def query_otx(ip: str) -> dict[str, Any]:
    if config.OTX_API_KEY:
        try:
            import httpx

            resp = httpx.get(
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                headers={"X-OTX-API-KEY": config.OTX_API_KEY},
                timeout=4.0,
            )
            resp.raise_for_status()
            pulses = resp.json().get("pulse_info", {}).get("count", 0)
            score = min(int(pulses), 10) / 10 * 100
            return _source_result(
                "otx",
                score,
                available=True,
                malicious=int(pulses) >= 3,
                detail=f"{pulses} tehdit bülteni (pulse)",
            )
        except Exception as exc:
            logger.warning("OTX query failed for %s: %s", ip, exc)

    score = _offline_score(ip)
    return _source_result(
        "otx",
        score,
        available=False,
        malicious=score >= 60,
        detail="offline tahmin (anahtar yok)",
    )


def get_threat_score(ip_address: str) -> dict[str, Any]:
    """
    Üç kaynaktan (VirusTotal, AbuseIPDB, OTX) sorgular, her birini 1-10'a
    normalize eder ve ağırlıklı ortalama 'Weighted Risk Score' üretir.

    KRİTİK koşulu: VirusTotal 'malicious' VEYA AbuseIPDB skoru %50 üzeri.
    """
    ip = ip_address.strip()

    if _is_internal_ip(ip):
        return {
            "ip": ip,
            "weighted_score_1_10": 1.0,
            "weighted_score_0_100": 0,
            "verdict": "internal",
            "is_critical": False,
            "sources": [],
            "detail": "Özel/iç ağ adresi — dış itibar sorgulanmaz",
        }

    sources = [query_virustotal(ip), query_abuseipdb(ip), query_otx(ip)]
    weights = config.TI_WEIGHTS

    weight_map = {
        "virustotal": weights.get("virustotal", 0.45),
        "abuseipdb": weights.get("abuseipdb", 0.35),
        "otx": weights.get("otx", 0.20),
    }
    total_weight = sum(weight_map[s["source"]] for s in sources) or 1.0
    weighted_1_10 = sum(s["normalized"] * weight_map[s["source"]] for s in sources) / total_weight
    weighted_1_10 = round(weighted_1_10, 1)
    weighted_0_100 = int(round((weighted_1_10 - 1) / 9 * 100))

    vt = next((s for s in sources if s["source"] == "virustotal"), None)
    abuse = next((s for s in sources if s["source"] == "abuseipdb"), None)
    is_critical = bool(
        (vt and vt["malicious"]) or (abuse and abuse["score_0_100"] >= 50)
    )

    if is_critical:
        verdict = "malicious"
    elif weighted_0_100 >= 30:
        verdict = "suspicious"
    elif weighted_0_100 >= 10:
        verdict = "unknown"
    else:
        verdict = "clean"

    detail = " · ".join(
        f"{s['source'].upper()} {s['normalized']}/10" for s in sources
    )

    return {
        "ip": ip,
        "weighted_score_1_10": weighted_1_10,
        "weighted_score_0_100": weighted_0_100,
        "verdict": verdict,
        "is_critical": is_critical,
        "sources": sources,
        "detail": detail,
    }


def check_ip(ip: str) -> dict[str, Any]:
    """Tek bir IP'yi çoklu kaynakla değerlendir (önbellekli)."""
    ip = ip.strip()
    if ip in _IP_CACHE:
        return _IP_CACHE[ip]

    ti = get_threat_score(ip)

    if ti["verdict"] == "internal":
        result = {
            "ioc": ip,
            "type": "ip",
            "risk_score": 0,
            "verdict": "internal",
            "source": "local",
            "detail": "Özel/iç ağ adresi",
            "is_critical": False,
            "ti": ti,
        }
        _IP_CACHE[ip] = result
        return result

    score_0_100 = ti["weighted_score_0_100"]
    active_sources = [s["source"] for s in ti["sources"] if s["available"]]
    source_label = "+".join(active_sources) if active_sources else "yerleşik/sezgisel"

    result = {
        "ioc": ip,
        "type": "ip",
        "risk_score": score_0_100,
        "verdict": ti["verdict"],
        "source": source_label,
        "detail": ti["detail"],
        "is_critical": ti["is_critical"],
        "ti": ti,
    }
    _IP_CACHE[ip] = result
    return result


def check_domain(domain: str) -> dict[str, Any]:
    domain = domain.strip().lower()
    score = KNOWN_BAD_DOMAINS.get(domain, 0)
    if score:
        return {
            "ioc": domain,
            "type": "domain",
            "risk_score": score,
            "verdict": "malicious" if score >= 75 else "suspicious",
            "source": "yerleşik liste",
            "detail": "Bilinen zararlı alan adı (C2/dağıtım)",
        }
    return {
        "ioc": domain,
        "type": "domain",
        "risk_score": 5,
        "verdict": "unknown",
        "source": "—",
        "detail": "İtibar verisi yok",
    }


def check_file(name: str) -> dict[str, Any]:
    key = name.strip().lower()
    for needle, score in SUSPICIOUS_FILES.items():
        if needle in key:
            return {
                "ioc": name,
                "type": "file",
                "risk_score": score,
                "verdict": "malicious" if score >= 75 else "suspicious",
                "source": "yerleşik liste",
                "detail": "Şüpheli/zararlı dosya veya araç imzası",
            }
    return {
        "ioc": name,
        "type": "file",
        "risk_score": 0,
        "verdict": "clean",
        "source": "local",
        "detail": "Bilinen kötü imza yok",
    }


def extract_iocs(raw: Any) -> dict[str, list[str]]:
    """raw_data içinden IP, domain ve dosya IoC'lerini çıkar."""
    iocs: dict[str, list[str]] = {"ips": [], "domains": [], "files": []}
    if not isinstance(raw, dict):
        return iocs

    text_fields = []
    for key in ("destination", "c2_host", "url", "remote_ip", "src_ip", "ip", "target", "attachment", "process"):
        value = raw.get(key)
        if value:
            text_fields.append(str(value))

    blob = " ".join(text_fields)

    for ip in _IP_RE.findall(blob):
        if ip not in iocs["ips"]:
            iocs["ips"].append(ip)

    for domain in _DOMAIN_RE.findall(blob):
        # IP'leri domain regex'i de yakalayabilir; ayıkla
        if _IP_RE.fullmatch(domain):
            continue
        # dosya uzantıları (exe, zip) domain gibi görünebilir → dosyaya yönlendir
        if domain.lower().split(".")[-1] in {"exe", "zip", "dll", "log", "ps1", "bat"}:
            if domain not in iocs["files"]:
                iocs["files"].append(domain)
        elif domain not in iocs["domains"]:
            iocs["domains"].append(domain)

    # Doğrudan dosya/araç alanları
    for key in ("target", "attachment", "process", "tool"):
        value = raw.get(key)
        if value and not _IP_RE.search(str(value)):
            v = str(value)
            if v not in iocs["files"] and v not in iocs["domains"]:
                iocs["files"].append(v)

    return iocs


def assess_log(log: dict[str, Any] | None) -> dict[str, Any]:
    """Bir logun IoC'lerini değerlendirip toplu risk skoru üret."""
    if not log:
        return _empty_result()

    raw = log.get("raw_data") or {}
    iocs = extract_iocs(raw)
    indicators: list[dict[str, Any]] = []

    for ip in iocs["ips"]:
        indicators.append(check_ip(ip))
    for domain in iocs["domains"]:
        indicators.append(check_domain(domain))
    for f in iocs["files"]:
        indicators.append(check_file(f))

    if not indicators:
        return _empty_result()

    top = max(indicators, key=lambda i: i["risk_score"])
    score = top["risk_score"]
    verdict = top["verdict"]
    any_critical = any(i.get("is_critical") for i in indicators)
    is_malicious = any_critical or (score >= 75 and verdict in {"malicious", "suspicious"})

    if any_critical or verdict == "malicious":
        note = f"⚠ {top['ioc']} → BİLİNEN ZARARLI ({top['source']}: {top['detail']})"
    elif verdict == "suspicious":
        note = f"⚠ {top['ioc']} → şüpheli ({top['detail']})"
    elif verdict == "internal":
        note = f"{top['ioc']} → iç ağ adresi, dış itibar yok"
    elif verdict == "clean":
        note = f"{top['ioc']} → temiz görünüyor"
    else:
        note = f"{top['ioc']} → itibar verisi bulunamadı"

    return {
        "risk_score": score,
        "verdict": verdict,
        "is_malicious": is_malicious,
        "is_critical": any_critical,
        "note": note,
        "primary_ioc": top["ioc"],
        "indicators": indicators,
        "source": top["source"],
    }


def assess_alert(alert: dict[str, Any]) -> dict[str, Any]:
    """Alarmın eşleşen logundan IoC değerlendirmesi yap (önbellekli)."""
    alert_id = str(alert.get("id") or "")
    if alert_id and alert_id in _ASSESS_CACHE:
        return _ASSESS_CACHE[alert_id]

    log = None
    matched_log_id = alert.get("matched_log_id")
    if matched_log_id:
        try:
            log = get_log_by_id(str(matched_log_id))
        except Exception:
            logger.warning("Threat intel: log fetch failed for alert %s", alert_id)
            log = None

    result = assess_log(log)
    if alert_id:
        _ASSESS_CACHE[alert_id] = result
    return result


def clear_cache() -> None:
    _ASSESS_CACHE.clear()
    _IP_CACHE.clear()
