<div align="center">

# 🛡️ CyberLens

### Bulut Tabanlı Tespit Mühendisliği & SOC Platformu

*Saldırı simülasyonu → log toplama → yapay zeka analizi → otomatik müdahale → canlı izleme*

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white)
![Streamlit](https://img.shields.io/badge/Streamlit-1.36+-FF4B4B?logo=streamlit&logoColor=white)
![Supabase](https://img.shields.io/badge/Supabase-PostgreSQL-3ECF8E?logo=supabase&logoColor=white)
![License](https://img.shields.io/badge/Lisans-E%C4%9Fitim%2FLab-blue)

</div>

---

## 📖 CyberLens Nedir?

**CyberLens**, gerçek bir **SOC (Security Operations Center)** iş akışını taklit eden mini bir tespit mühendisliği laboratuvarıdır. Dışarıdan gelen güvenlik loglarını toplar, yapay zeka / sezgisel motorla analiz eder, tehditler için kural ve alarm üretir, çoklu kaynaktan tehdit istihbaratı toplar ve isteğe bağlı olarak **otomatik müdahale (SOAR)** uygular.

> **Basitçe:** Sahte saldırı logları gönderirsin → sistem tehdidi yakalar → alarm üretir → panelde izlersin → istersen otomatik müdahale eder.

---

## ✨ Öne Çıkan Özellikler

| Özellik | Açıklama |
| --- | --- |
| 🔍 **Tespit Motoru** | Cursor LLM + sezgisel yedek; loglardan KQL tespit kuralları üretir |
| 🚨 **Otomatik Alarm** | Tehdit bulunan her log için otomatik alarm + NIST/OWASP/MITRE etiketi |
| ⚡ **SOAR Otomatik Müdahale** | Global anahtarla; tehditte playbook çalıştırır (IP engelle, host izole, kullanıcı kapat) |
| 🛰 **Çoklu Kaynak Tehdit İstihbaratı** | VirusTotal + AbuseIPDB + OTX → ağırlıklı risk skoru (1–10) + KRİTİK işaretleme |
| 🕓 **Adli Zaman Çizelgesi** | Bir alarmın saldırganına ait tüm hareketleri kronolojik dizer |
| 📊 **Canlı SOC Paneli** | Supabase Realtime ile anlık alarm akışı, açık/arşiv sekmeleri, grafikler |
| 🧪 **Saldırı Lab (poc-lab)** | 20 senaryoluk havuzdan rastgele saldırı + rastgele IP üretici |
| 📑 **Günlük Rapor** | Kritik alarmların executive summary çıktısı (MD/JSON) |

---

## 🏗️ Mimari

```
┌──────────────────┐         ┌─────────────────────────────────────────────┐
│  🧪 Saldırı Lab   │  log    │            🛡️ Güvenlik Paneli (SOC)           │
│   (poc-lab)       │ ──────► │                                               │
│ rastgele saldırı  │         │  log_processor → ai_engine → alert_engine     │
│ + rastgele IP     │         │       │              │             │          │
└──────────────────┘         │       ▼              ▼             ▼          │
                             │   Supabase        threat_intel  response_engine│
                             │   (logs/rules/    (VT+Abuse+OTX) (SOAR playbook)│
                             │    alerts)            │             │          │
                             │       │               ▼             ▼          │
                             │       └──► Realtime UI ◄── forensic_engine      │
                             └─────────────────────────────────────────────┘
```

| Katman | Bileşen | Sorumluluk |
| --- | --- | --- |
| Ingestion | `src/log_processor.py` | Log temizleme + batch buffer (5 sn / 10 kayıt) |
| Persistence | `src/database.py` | Supabase CRUD — logs, rules, alerts, platform_settings |
| Detection | `src/ai_engine.py` | LLM/sezgisel tehdit analizi + KQL üretimi |
| Alerting | `src/alert_engine.py` | Kural sonrası otomatik alarm |
| **SOAR** | `src/response_engine.py` | Otomatik playbook müdahalesi |
| **Threat Intel** | `src/threat_intel.py` | Çoklu kaynak IoC skorlama + KRİTİK tespiti |
| **Forensics** | `src/forensic_engine.py` | Saldırgan zaman çizelgesi rekonstrüksiyonu |
| Orchestration | `src/pipeline.py` | Ingest → analyze → alert → report |
| Reporting | `src/reporter.py` | Günlük kritik alarm raporu |
| UI | `app.py`, `src/ui/` | Streamlit çok sayfalı dashboard |

---

## 🚀 Hızlı Başlangıç

### 1. Bağımlılıklar

```bash
pip install -r requirements.txt
```

### 2. Ortam Değişkenleri

```bash
cp .env.example .env
```

| Değişken | Gerekli mi? | Açıklama |
| --- | --- | --- |
| `SUPABASE_URL` | ✅ | Supabase proje URL'si |
| `SUPABASE_KEY` | ✅ | Publishable / anon anahtar |
| `CURSOR_API_KEY` | ⭕ | Yapay zeka analizi için (yoksa sezgisel mod) |
| `ABUSEIPDB_API_KEY` | ⭕ | Tehdit istihbaratı (yoksa offline demo) |
| `VIRUSTOTAL_API_KEY` | ⭕ | Tehdit istihbaratı (yoksa offline demo) |
| `OTX_API_KEY` | ⭕ | AlienVault OTX (yoksa offline demo) |
| `SUPABASE_DB_PASSWORD` | ⭕ | Sadece migration script için |

> Hiçbir opsiyonel anahtar olmadan da platform tamamen çalışır — sezgisel analiz ve offline tehdit istihbaratı devreye girer.

### 3. Veritabanı Şeması

```bash
python scripts/apply_schema.py
```

### 4. Sağlık Kontrolü

```bash
python scripts/health_check.py
```

### 5. Paneli Başlat

```bash
streamlit run app.py
```

---

## 🎮 Kullanım

Panel iki sayfadan oluşur:

### 🛡️ Güvenlik Paneli
- Canlı alarm akışı (açık / arşiv sekmeleri)
- 🛰 Canlı tehdit istihbaratı özeti
- 🕓 Adli zaman çizelgesi
- Kural üretici (KQL + sade dil açıklama)
- Sol panelde **⚡ SOAR otomatik müdahale** anahtarı

### 🧪 Saldırı Lab
- Rastgele saldırı senaryosu üret (20 şablon)
- Rastgele zararlı/zararsız IP blokları
- "Logları sisteme gönder" + otomatik analiz

### Tipik akış

```bash
# 1) Test logları gönder + analiz et + alarm üret
python lab/poc_lab_simulator.py --count 6 --full

# 2) Paneli aç
streamlit run app.py

# 3) Günlük kritik alarm raporu
python -m src.reporter
```

---

## 🧠 Tespit Kuralları

Her log analiz edildiğinde:

1. **Tehdit tespiti** — LLM veya sezgisel motor logu inceler
2. **KQL üretimi** — Microsoft Sentinel uyumlu tespit sorgusu
3. **Framework eşlemesi** — `NIST:DE.AE; OWASP:A07:2021; MITRE:T1003`
4. **Alarm** — önem derecesine göre SOC paneline düşer

---

## ⚡ SOAR — Otomatik Müdahale

Sol paneldeki anahtar açıkken, tehdit tespit edilen alarmlar analist onayı beklemeden otomatik işlenir:

| Olay türü | Otomatik aksiyonlar |
| --- | --- |
| Yanal hareket | IP engelle · host izole · SOC bildir |
| Kimlik erişimi | kullanıcı devre dışı · parola sıfırla · host izole |
| PowerShell | process karantina · host izole |
| Veri sızdırma | IP engelle · host izole |

> Aksiyonlar simülasyondur (gerçek firewall'a bağlı değil) — playbook mantığını gösterir.

---

## 🛰 Tehdit İstihbaratı (Threat Intelligence)

`get_threat_score(ip)` fonksiyonu üç kaynağı sorgular ve **ağırlıklı risk skoru** üretir:

| Kaynak | Ağırlık | Normalize |
| --- | --- | --- |
| VirusTotal | %45 | zararlı motor oranı → 1–10 |
| AbuseIPDB | %35 | güven skoru → 1–10 |
| AlienVault OTX | %20 | pulse sayısı → 1–10 |

**KRİTİK** koşulu: VirusTotal `malicious` **veya** AbuseIPDB skoru ≥ %50 → alarm kartı kırmızı çerçeveye alınır.

---

## 📁 Proje Yapısı

```
CyberLens/
├── app.py                       # Çok sayfalı Streamlit giriş noktası
├── config.py                    # Ortam değişkenleri
├── requirements.txt
├── src/
│   ├── database.py              # Supabase veri erişimi
│   ├── log_processor.py         # Batch log ingestion + temizleme
│   ├── ai_engine.py             # LLM/sezgisel tespit motoru
│   ├── alert_engine.py          # Otomatik alarm
│   ├── response_engine.py       # SOAR otomatik müdahale
│   ├── threat_intel.py          # Çoklu kaynak tehdit istihbaratı
│   ├── forensic_engine.py       # Adli zaman çizelgesi
│   ├── pipeline.py              # End-to-end orchestrator
│   ├── reporter.py              # Günlük kritik alarm raporu
│   ├── logging_config.py        # Merkezi loglama
│   └── ui/
│       ├── soc_page.py          # Güvenlik paneli
│       ├── lab_page.py          # Saldırı lab sayfası
│       ├── dashboard_common.py  # Paylaşılan UI bileşenleri
│       ├── cyber_theme.py       # Siber tema + alarm kartları
│       └── rule_explainer.py    # Kural açıklamaları
├── supabase/migrations/         # PostgreSQL şema migration'ları
├── scripts/                     # apply_schema, run_pipeline, health_check
├── lab/poc_lab_simulator.py     # poc-lab + rastgele IP üretici
└── data/                        # logs/ + reports/
```

---

## 🗄️ Veri Modeli

**logs** → ham/normalize olaylar · **rules** → tespit kuralları (KQL + standard) · **alerts** → alarmlar (status, severity, metadata) · **platform_settings** → global SOAR anahtarı

---

## 🔒 Güvenlik Notları

- Tüm kimlik bilgileri `.env` üzerinden yönetilir, repoya **commit edilmez**.
- Supabase tablolarında Row Level Security (RLS) etkindir.
- Bu platform **eğitim ve laboratuvar** amaçlıdır; üretim ortamı için sertleştirme gerekir.

---

## 📜 Lisans

Eğitim ve tespit mühendisliği laboratuvar kullanımı için geliştirilmiştir.

<div align="center">

**CyberLens** · Detection Engineering Lab 🛡️

</div>
