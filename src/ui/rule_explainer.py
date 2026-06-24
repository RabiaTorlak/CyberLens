"""Türkçe kural açıklamaları — panelde okunabilir özetler."""

from __future__ import annotations

from typing import Any

RULE_GENERATOR_HELP = """
**Tespit kuralı nedir?**  
Loglarda belirli bir **şüpheli kalıbı** arayan otomatik sorgudur. Eşleşme bulunursa **alarm** üretilir.

**KQL nedir?**  
Microsoft Sentinel / Azure Monitor'da kullanılan sorgu dili. Gerçek ortamda bu sorguyu SIEM'e yapıştırırsın;  
burada **demo** amaçlı üretiliyor.

**Akış:** Log gelir → analiz motoru tehdit görür → kural + alarm oluşur.
"""

RULE_NAME_TR: dict[str, str] = {
    "Suspicious Credential Access": (
        "Kimlik bilgisi erişimi tespiti — parola, oturum veya bellekten credential çalma girişimleri."
    ),
    "Lateral Movement Detected": (
        "Yanal hareket — saldırganın ele geçirdiği bir makineden ağdaki diğer sunuculara sıçraması."
    ),
    "Suspicious PowerShell Execution": (
        "Şüpheli PowerShell — genelde zararlı script, indir-çalıştır veya keşif komutları."
    ),
    "Suspicious Execution Activity": (
        "Şüpheli process çalıştırma — cmd, rundll32 vb. ile yetkisiz komut denemeleri."
    ),
    "Potential Data Exfiltration": (
        "Veri sızdırma şüphesi — büyük dış trafik, DNS tüneli veya dışarı dosya aktarımı."
    ),
    "Anomalous Lab Event": (
        "Standart listeye uymayan ama olağandışı bir lab olayı — manuel inceleme önerilir."
    ),
}

STANDARD_GLOSSARY: dict[str, str] = {
    "NIST:DE.AE": "NIST · Anomali ve güvenlik olaylarını tespit et",
    "NIST:DE.CM": "NIST · Güvenlik sürekli izleme",
    "NIST:DE.CM-1": "NIST · Ağ izleme ve anomali tespiti",
    "NIST:PR.AC-1": "NIST · Kimlik ve erişim yönetimi",
    "NIST:PR.DS-1": "NIST · Veri koruma (sızdırma önleme)",
    "NIST:PR.PT-1": "NIST · İletişim koruması",
    "NIST:RS.AN-1": "NIST · Olay analizi ve soruşturma",
    "OWASP:A01:2021": "OWASP · Bozuk erişim kontrolü",
    "OWASP:A02:2021": "OWASP · Kriptografik hatalar / veri sızıntısı",
    "OWASP:A03:2021": "OWASP · Enjeksiyon / kötü amaçlı girdi",
    "OWASP:A07:2021": "OWASP · Kimlik doğrulama hataları",
    "OWASP:A09:2021": "OWASP · Güvenlik günlüğü ve izleme eksiklikleri",
    "MITRE:T1003": "MITRE T1003 · İşletim sistemi credential dump",
    "MITRE:T1021": "MITRE T1021 · Uzak servislerle yanal hareket",
    "MITRE:T1021.001": "MITRE T1021.001 · RDP ile yanal hareket",
    "MITRE:T1021.002": "MITRE T1021.002 · SMB/Admin paylaşımı ile hareket",
    "MITRE:T1021.003": "MITRE T1021.003 · DCOM/WMI ile hareket",
    "MITRE:T1059": "MITRE T1059 · Komut satırı yorumlayıcıları",
    "MITRE:T1059.001": "MITRE T1059.001 · PowerShell",
    "MITRE:T1059.003": "MITRE T1059.003 · Windows Command Shell",
    "MITRE:T1041": "MITRE T1041 · C2 kanalı üzerinden exfil",
    "MITRE:T1078": "MITRE T1078 · Geçerli hesapların kötüye kullanımı",
}


def explain_standard(standard: str) -> list[str]:
    if not standard or standard == "—":
        return []
    parts = [part.strip() for part in standard.split(";") if part.strip()]
    lines: list[str] = []
    for part in parts:
        lines.append(STANDARD_GLOSSARY.get(part, part))
    return lines


def summarize_kql(kql: str) -> list[str]:
    if not kql.strip():
        return ["Sorgu metni henüz üretilmedi."]

    text = kql.lower()
    steps: list[str] = []

    if "securityevent" in text:
        steps.append("Windows **SecurityEvent** tablosundaki güvenlik kayıtlarını tarar.")
    if "ago(24h)" in text or "ago(1d)" in text:
        steps.append("Son **24 saat** içindeki olaylara bakar.")
    if "eventid" in text:
        steps.append("Belirli **Event ID** değerlerine göre filtreler (logon, process oluşturma vb.).")
    if "computer has" in text or "account has" in text:
        steps.append("Belirli **bilgisayar** veya **kullanıcı hesabı** ile sınırlar.")
    if "process has" in text or "commandline has" in text:
        steps.append("Process adı veya **komut satırında** şüpheli anahtar kelime arar.")
    if "order by timegenerated desc" in text:
        steps.append("Sonuçları **en yeni olay üstte** olacak şekilde sıralar.")

    if not steps:
        steps.append("Log tablolarında eşleşen şüpheli kalıpları arayan bir tespit sorgusudur.")

    steps.append("Eşleşme bulunursa SOC ekibine **alarm** düşer; sen de sol panelden incelersin.")
    return steps


def get_rule_summary(rule: dict[str, Any]) -> str:
    name = str(rule.get("name") or "").strip()
    if name in RULE_NAME_TR:
        return RULE_NAME_TR[name]

    description = str(rule.get("description") or "").strip()
    if description:
        return description

    return "Bu kural, seçilen logdaki şüpheli davranışı tekrar yakalamak için otomatik üretildi."


def get_rule_action_hint(severity: str) -> str:
    sev = str(severity or "medium").lower()
    hints = {
        "critical": "Hemen incele — veri kaybı veya aktif saldırı ihtimali yüksek.",
        "high": "Öncelikli incele — kimlik veya yanal hareket riski var.",
        "medium": "Planlı incele — şüpheli aktivite; bağlamı doğrula.",
        "low": "Düşük öncelik — bilgi amaçlı veya zayıf sinyal.",
    }
    return hints.get(sev, hints["medium"])
