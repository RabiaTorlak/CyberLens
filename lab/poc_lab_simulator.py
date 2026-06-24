"""poc-lab attack simulation log sender.

Usage:
    python lab/poc_lab_simulator.py
    python lab/poc_lab_simulator.py --full   # ingest + analyze + alerts
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.log_processor import LogProcessor  # noqa: E402
from src.pipeline import Pipeline  # noqa: E402


SAMPLE_EVENTS = [
    {
        "source": "poc-lab",
        "event": "powershell_execution",
        "host": "LAB-WS01",
        "user": "admin",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": {"command": "Get-Process", "technique": "T1059.001"},
    },
    {
        "source": "poc-lab",
        "event": "lateral_movement",
        "host": "LAB-DC01",
        "user": "SYSTEM",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": {"tool": "psexec", "technique": "T1021.002"},
    },
    {
        "source": "poc-lab",
        "event": "credential_access",
        "host": "LAB-WS01",
        "user": "admin",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": {"technique": "T1003", "target": "lsass.exe"},
    },
]


def main() -> None:
    parser = argparse.ArgumentParser(description="poc-lab log simulator")
    parser.add_argument(
        "--full",
        action="store_true",
        help="Ingest sample logs and run analysis pipeline",
    )
    args = parser.parse_args()

    if args.full:
        result = Pipeline().run_full(SAMPLE_EVENTS, analyze=True)
        print(
            f"Pipeline: ingested={result.logs_ingested} "
            f"rules={result.rules_created} alerts={result.alerts_created}"
        )
        return

    processor = LogProcessor(auto_start=False)
    cleaned = processor.process_many(SAMPLE_EVENTS)
    flushed = processor.shutdown()
    print(f"Processed {len(cleaned)} log(s), flushed {flushed} to Supabase.")


if __name__ == "__main__":
    main()
