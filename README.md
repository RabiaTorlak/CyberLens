# logtut — Cloud-Native Detection Engineering Platform

**logtut**, saldırı simülasyonu ortamlarından (`poc-lab`) gelen telemetriyi işleyen, LLM destekli tespit kuralları üreten ve **Supabase Realtime Monitoring** ile canlı alarm akışı sunan bir **Detection Engineering** platformudur. Mimari, **Cloud-Native Security** prensiplerine uygun olarak durumsuz (stateless) servis katmanları, yönetilen PostgreSQL backend ve olay güdümlü (event-driven) veri akışı üzerine kurulmuştur.

---

## Mimari Genel Bakış

```
poc-lab ──► log_processor ──► Supabase (logs)
                                    │
                                    ▼
                              ai_engine (Cursor LLM)
                                    │
                                    ▼
                              Supabase (rules)
                                    │
                    ┌───────────────┴───────────────┐
                    ▼                               ▼
            app.py (Realtime UI)              reporter.py
         Supabase Realtime WS              Daily Critical Report
```

| Katman | Bileşen | Sorumluluk |
| --- | --- | --- |
| Ingestion | `src/log_processor.py` | Log temizleme, batch buffer (5s / 10 kayıt) |
| Persistence | `src/database.py` | supabase-py CRUD — `logs`, `rules`, `alerts` |
| Detection | `src/ai_engine.py` | Cursor SDK ile tehdit analizi + KQL üretimi |
| Monitoring | `app.py` | Streamlit dashboard, **Supabase Realtime Monitoring** |
| Reporting | `src/reporter.py` | Günlük kritik alarm özet raporu |
| Orchestration | `src/pipeline.py` | Ingest → analyze → alert zinciri |
| Alerting | `src/alert_engine.py` | Kural sonrası otomatik alarm oluşturma |
| Observability | `src/logging_config.py` | Merkezi, rotasyonlu loglama |

---

## Detection Engineering Yetenekleri

Platform, modern **Detection Engineering** yaşam döngüsünün temel adımlarını otomatikleştirir:

1. **Telemetri toplama** — poc-lab araçlarından gelen ham olaylar normalize edilir.
2. **Kural geliştirme** — Cursor LLM, log bağlamından KQL detection sorguları üretir.
3. **Framework eşlemesi** — NIST CSF, OWASP Top 10 ve MITRE ATT&CK referansları `rules.standard` alanına yazılır.
4. **Operasyonel geri bildirim** — Alarmlar Realtime kanalı üzerinden SOC dashboard'una akar.
5. **Raporlama** — Kritik alarmlar günlük executive summary formatında arşivlenir.

---

## Cloud-Native Security Tasarımı

- **Yönetilen veritabanı:** Supabase PostgreSQL — RLS, JSONB telemetri, publication tabanlı Realtime.
- **Durumsuz uygulama katmanı:** Python modülleri horizontal scale için uygun; state Supabase'te tutulur.
- **Olay güdümlü izleme:** `alerts` tablosundaki INSERT olayları WebSocket ile dashboard'a iletilir — klasik polling yerine push-tabanlı **Supabase Realtime Monitoring**.
- **Batch ingestion:** Yüksek hacimli log akışında API throttling'i önlemek için buffer + toplu INSERT.
- **Secrets yönetimi:** Tüm kimlik bilgileri `.env` üzerinden; repoya commit edilmez.

---

## Proje Yapısı

```
logtut/
├── app.py                          # Streamlit dashboard
├── config.py                       # Ortam değişkenleri
├── requirements.txt
├── src/
│   ├── database.py                 # Supabase veri erişim katmanı
│   ├── log_processor.py            # Batch log ingestion + cleaning
│   ├── ai_engine.py                # Cursor LLM tespit motoru
│   ├── alert_engine.py             # Otomatik alarm oluşturma
│   ├── pipeline.py                 # End-to-end orchestrator
│   ├── reporter.py                 # Günlük kritik alarm raporu
│   └── logging_config.py           # Merkezi logging
├── supabase/migrations/            # PostgreSQL şema migration'ları
├── scripts/
│   ├── apply_schema.py
│   ├── run_pipeline.py
│   ├── health_check.py
│   └── set_cursor_key.py
├── data/
│   ├── logs/                       # platform.log (rotating)
│   └── reports/                    # Günlük rapor çıktıları
├── rules/                          # Sigma/YARA kural dosyaları (lab)
└── lab/                            # poc-lab simülasyon araçları
```

---

## Kurulum

### 1. Bağımlılıklar

```bash
pip install -r requirements.txt
```

### 2. Ortam Değişkenleri

`.env.example` dosyasını kopyalayın:

```bash
cp .env.example .env
```

| Değişken | Açıklama |
| --- | --- |
| `SUPABASE_URL` | Supabase proje URL |
| `SUPABASE_KEY` | Publishable / anon key |
| `CURSOR_API_KEY` | Cursor SDK API anahtarı |
| `CURSOR_MODEL` | LLM model (varsayılan: `composer-2.5`) |
| `LOG_LEVEL` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `SUPABASE_DB_PASSWORD` | Migration script için DB şifresi |

### 3. Veritabanı Şeması

```bash
python scripts/apply_schema.py
```

Migration'lar sırasıyla uygulanır:

- `001_initial_schema.sql` — `rules`, `logs`, `alerts` tabloları
- `002_add_rules_standard.sql` — NIST/OWASP `standard` sütunu
- `003_enable_realtime_alerts.sql` — Realtime publication

---

## Kullanım

### Log Ingestion (poc-lab)

```python
from src.log_processor import get_processor

processor = get_processor()
processor.process({
    "source": "poc-lab",
    "event": "lateral_movement",
    "host": "TARGET-01",
    "user": "SYSTEM",
    "timestamp": "2026-06-21T14:30:00Z",
    "data": {"technique": "T1021"},
})
processor.shutdown()  # kalan buffer'ı flush eder
```

### AI Tespit Motoru

```python
from src.ai_engine import AIEngine

engine = AIEngine()
rule = engine.analyze_log_by_id("<log-uuid>")
```

CLI:

```bash
python -m src.ai_engine <log_id>
```

### Dashboard (Supabase Realtime Monitoring)

```bash
streamlit run app.py
```

Dashboard özellikleri:

- **Canlı alarmlar** — Supabase Realtime `INSERT` subscription
- **Ağ trafiği grafiği** — Plotly bar chart (log dağılımı)
- **KQL Kuralı Üret** — Seçili log için `AIEngine.analyze_and_save()` tetikler

### End-to-End Pipeline

Tek komutla tüm akışı çalıştırın (ingest → analyze → rule + alert):

```bash
python scripts/run_pipeline.py --full
```

Adım adım:

```bash
python lab/poc_lab_simulator.py --full
python scripts/run_pipeline.py --analyze
python scripts/run_pipeline.py --report
```

### Günlük Kritik Alarm Raporu

```bash
python -m src.reporter
python -m src.reporter 2026-06-21
```

Çıktılar: `data/reports/critical-alerts-YYYY-MM-DD.{md,json}`

---

### `logs`

| Sütun | Tip | Açıklama |
| --- | --- | --- |
| `source` | TEXT | Log kaynağı (ör. `poc-lab`) |
| `event_type` | TEXT | Olay tipi |
| `hostname` | TEXT | Hedef sistem |
| `username` | TEXT | İlgili kullanıcı |
| `raw_data` | JSONB | Ham/normalize edilmiş payload |
| `event_time` | TIMESTAMPTZ | Olay zamanı |

### `rules`

| Sütun | Tip | Açıklama |
| --- | --- | --- |
| `name` | TEXT | Kural adı |
| `content` | TEXT | KQL sorgusu |
| `rule_type` | TEXT | `kql`, `sigma`, `custom` |
| `severity` | TEXT | `low` \| `medium` \| `high` \| `critical` |
| `standard` | TEXT | `NIST:DE.AE; OWASP:A01:2021; MITRE:T1059` |
| `metadata` | JSONB | LLM analizi, kaynak log ID |

### `alerts`

| Sütun | Tip | Açıklama |
| --- | --- | --- |
| `title` | TEXT | Alarm başlığı |
| `severity` | TEXT | Önem derecesi |
| `status` | TEXT | `open` \| `investigating` \| `resolved` \| `false_positive` |
| `rule_id` | UUID | İlişkili detection rule |
| `matched_log_id` | UUID | Tetikleyen log |

---

## Loglama ve Hata Yönetimi

Merkezi logging `src/logging_config.py` üzerinden yapılandırılır:

- **Console** — stderr, yapılandırılabilir seviye
- **File** — `data/logs/platform.log` (5 MB rotasyon, 5 yedek)
- **Logger namespace** — `logtut.database`, `logtut.ai_engine`, `logtut.reporter`, ...

Tüm Supabase API çağrıları `postgrest.exceptions.APIError` yakalanır ve `logger.exception()` ile kaydedilir. Buffer flush hatalarında loglar kuyruğa geri yüklenir (data loss önleme).

```python
from src.logging_config import get_logger

logger = get_logger("my_module")
logger.info("Operation completed")
```

---

## Supabase Realtime Monitoring

`alerts` tablosu `supabase_realtime` publication'a eklenmiştir. Dashboard, `postgres_changes` kanalı üzerinden yalnızca `INSERT` olaylarını dinler:

```python
channel = client.channel("dashboard-alerts")
channel.on_postgres_changes(
    event="INSERT",
    schema="public",
    table="alerts",
    callback=handler,
).subscribe()
```

Bu yaklaşım, **Cloud-Native Security** operasyonlarında düşük gecikmeli (low-latency) alarm triage sağlar; polling tabanlı çözümlere kıyasla API yükünü ve algılama gecikmesini azaltır.

---

## Geliştirme Notları

- Buffer eşikleri: `BATCH_INTERVAL_SECONDS=5`, `BATCH_SIZE_THRESHOLD=10` (`log_processor.py`)
- Realtime panel yenileme: 2 saniye (`app.py` `@st.fragment`)
- Raporlama penceresi: UTC gün sınırları (`reporter.py`)
- IPv6 olmayan ağlarda migration script otomatik pooler keşfi yapar (`apply_schema.py`)

---

## Lisans

Bu proje eğitim ve Detection Engineering laboratuvar kullanımı için geliştirilmiştir.
