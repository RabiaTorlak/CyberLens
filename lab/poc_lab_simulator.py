"""poc-lab attack simulation log sender.

Usage:
    python lab/poc_lab_simulator.py
    python lab/poc_lab_simulator.py --count 8
    python lab/poc_lab_simulator.py --full   # ingest + analyze + alerts
"""

from __future__ import annotations

import argparse
import random
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.log_processor import LogProcessor  # noqa: E402
from src.pipeline import Pipeline  # noqa: E402

HOSTS = ["LAB-WS01", "LAB-WS02", "LAB-DC01", "LAB-SRV03", "LAB-FILE01", "LAB-WEB01"]
USERS = ["admin", "SYSTEM", "svc_backup", "jdoe", "helpdesk", "guest"]

# Geniş saldırı senaryo havuzu — her gönderimde rastgele seçilir.
EVENT_CATALOG: list[dict[str, Any]] = [
    {
        "event": "powershell_execution",
        "data": {"command": "IEX (New-Object Net.WebClient).DownloadString(...)", "technique": "T1059.001"},
    },
    {
        "event": "powershell_execution",
        "data": {"command": "Invoke-Mimikatz", "technique": "T1059.001"},
    },
    {
        "event": "powershell_execution",
        "data": {"command": "Get-Process | Where-Object {$_.Name -eq 'lsass'}", "technique": "T1059.001"},
    },
    {
        "event": "lateral_movement",
        "data": {"tool": "psexec", "target_host": "LAB-DC01", "technique": "T1021.002"},
    },
    {
        "event": "lateral_movement",
        "data": {"tool": "wmic", "target_host": "LAB-SRV03", "technique": "T1021.003"},
    },
    {
        "event": "lateral_movement",
        "data": {"tool": "rdp", "target_host": "LAB-WS02", "technique": "T1021.001"},
    },
    {
        "event": "credential_access",
        "data": {"technique": "T1003", "target": "lsass.exe", "method": "memory_dump"},
    },
    {
        "event": "credential_access",
        "data": {"technique": "T1110", "target": "auth.log", "method": "brute_force"},
    },
    {
        "event": "credential_access",
        "data": {"technique": "T1555", "target": "browser_vault", "method": "credential_dump"},
    },
    {
        "event": "suspicious_execution",
        "data": {"process": "cmd.exe", "command_line": "/c whoami /all", "technique": "T1059.003"},
    },
    {
        "event": "suspicious_execution",
        "data": {"process": "rundll32.exe", "command_line": "shell32.dll,Control_RunDLL", "technique": "T1218.011"},
    },
    {
        "event": "data_exfiltration",
        "data": {"bytes_out": 524288000, "destination": "185.220.101.45", "technique": "T1041"},
    },
    {
        "event": "data_exfiltration",
        "data": {"channel": "dns_tunnel", "query_count": 842, "technique": "T1048.003"},
    },
    {
        "event": "malware_download",
        "data": {"url": "http://malicious.example/payload.exe", "technique": "T1105"},
    },
    {
        "event": "privilege_escalation",
        "data": {"technique": "T1068", "details": "UAC bypass via fodhelper"},
    },
    {
        "event": "persistence",
        "data": {"technique": "T1547.001", "registry_key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
    },
    {
        "event": "defense_evasion",
        "data": {"technique": "T1562.001", "action": "disabled_windows_defender"},
    },
    {
        "event": "phishing",
        "data": {"technique": "T1566.001", "subject": "Acil: fatura eki", "attachment": "invoice.zip"},
    },
    {
        "event": "reconnaissance",
        "data": {"technique": "T1046", "ports_scanned": "1-1024", "target": "192.168.10.0/24"},
    },
    {
        "event": "command_and_control",
        "data": {"technique": "T1071.001", "c2_host": "beacon.evil.net", "protocol": "https"},
    },
]


def _build_event(template: dict[str, Any]) -> dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    return {
        "source": "poc-lab",
        "event": template["event"],
        "host": random.choice(HOSTS),
        "user": random.choice(USERS),
        "timestamp": now,
        "data": {
            **template["data"],
            "simulation_id": str(uuid.uuid4())[:8],
        },
    }


def generate_sample_events(count: int = 6, *, seed: int | None = None) -> list[dict[str, Any]]:
    """Rastgele saldırı senaryoları üret. count, katalog boyutunu aşamaz."""
    if count < 1:
        raise ValueError("count must be at least 1")

    rng = random.Random(seed)
    pick_count = min(count, len(EVENT_CATALOG))
    templates = rng.sample(EVENT_CATALOG, k=pick_count)
    return [_build_event(template) for template in templates]


# Geriye dönük uyumluluk (eski scriptler)
SAMPLE_EVENTS = generate_sample_events(6, seed=42)


def main() -> None:
    parser = argparse.ArgumentParser(description="poc-lab log simulator")
    parser.add_argument(
        "--full",
        action="store_true",
        help="Ingest sample logs and run analysis pipeline",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=6,
        help="How many random attack scenarios to send (default: 6)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Optional RNG seed for reproducible batches",
    )
    args = parser.parse_args()

    events = generate_sample_events(args.count, seed=args.seed)

    if args.full:
        result = Pipeline().run_full(events, analyze=True)
        types = ", ".join(sorted({e["event"] for e in events}))
        print(
            f"Pipeline: ingested={result.logs_ingested} "
            f"rules={result.rules_created} alerts={result.alerts_created}"
        )
        print(f"Event types: {types}")
        return

    processor = LogProcessor(auto_start=False)
    cleaned = processor.process_many(events)
    flushed = processor.shutdown()
    print(f"Processed {len(cleaned)} log(s), flushed {flushed} to Supabase.")


if __name__ == "__main__":
    main()
