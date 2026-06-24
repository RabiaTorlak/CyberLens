"""CLI entry point for the Detection Engineering pipeline."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lab.poc_lab_simulator import SAMPLE_EVENTS  # noqa: E402
from src.logging_config import get_logger  # noqa: E402
from src.pipeline import Pipeline  # noqa: E402

logger = get_logger("run_pipeline")


def main() -> None:
    parser = argparse.ArgumentParser(description="Detection Engineering pipeline runner")
    parser.add_argument(
        "--ingest",
        action="store_true",
        help="Send poc-lab sample logs to Supabase",
    )
    parser.add_argument(
        "--analyze",
        action="store_true",
        help="Analyze unprocessed logs and create rules + alerts",
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Generate daily critical alert report",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=50,
        help="Max unprocessed logs to analyze (default: 50)",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Run ingest + analyze + report",
    )
    args = parser.parse_args()

    if args.full:
        args.ingest = True
        args.analyze = True
        args.report = True

    if not (args.ingest or args.analyze or args.report):
        parser.print_help()
        sys.exit(1)

    pipeline = Pipeline()
    raw_logs = SAMPLE_EVENTS if args.ingest else None

    try:
        result = pipeline.run_full(
            raw_logs,
            analyze=args.analyze,
            report=args.report,
            analyze_limit=args.limit,
        )
    except Exception:
        logger.exception("Pipeline failed")
        sys.exit(1)

    print(f"Ingested:  {result.logs_ingested}")
    print(f"Analyzed: {result.logs_analyzed}")
    print(f"Rules:    {result.rules_created}")
    print(f"Alerts:   {result.alerts_created}")
    if result.report_path:
        print(f"Report:   {result.report_path}")


if __name__ == "__main__":
    main()
