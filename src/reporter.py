"""Daily critical alert reporting."""

from __future__ import annotations

import json
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path
from typing import Any

import config
from src.database import get_critical_alerts_for_day
from src.logging_config import get_logger

logger = get_logger("reporter")


@dataclass
class DailyReport:
    report_date: date
    generated_at: datetime
    alerts: list[dict[str, Any]]
    summary: dict[str, Any]
    markdown: str
    json_payload: dict[str, Any]


def _day_bounds(report_date: date) -> tuple[datetime, datetime]:
    start = datetime.combine(report_date, time.min, tzinfo=timezone.utc)
    end = start + timedelta(days=1)
    return start, end


def _build_summary(alerts: list[dict[str, Any]]) -> dict[str, Any]:
    status_counts = Counter(alert.get("status", "unknown") for alert in alerts)
    rule_ids = [alert.get("rule_id") for alert in alerts if alert.get("rule_id")]

    return {
        "total_critical": len(alerts),
        "open": status_counts.get("open", 0),
        "investigating": status_counts.get("investigating", 0),
        "resolved": status_counts.get("resolved", 0),
        "false_positive": status_counts.get("false_positive", 0),
        "linked_rules": len(set(rule_ids)),
    }


def _format_alert_section(index: int, alert: dict[str, Any]) -> str:
    lines = [
        f"### {index}. {alert.get('title', 'Untitled Alert')}",
        "",
        f"- **ID:** `{alert.get('id', '—')}`",
        f"- **Status:** `{alert.get('status', '—')}`",
        f"- **Created:** `{alert.get('created_at', '—')}`",
    ]
    if alert.get("rule_id"):
        lines.append(f"- **Rule ID:** `{alert['rule_id']}`")
    if alert.get("matched_log_id"):
        lines.append(f"- **Matched Log:** `{alert['matched_log_id']}`")

    description = alert.get("description") or "No description provided."
    lines.extend(["", description, ""])
    return "\n".join(lines)


def build_markdown_report(
    alerts: list[dict[str, Any]],
    report_date: date,
    generated_at: datetime | None = None,
) -> str:
    generated_at = generated_at or datetime.now(timezone.utc)
    summary = _build_summary(alerts)
    day_start, day_end = _day_bounds(report_date)

    lines = [
        "# Daily Critical Alert Summary",
        "",
        "## Report Metadata",
        "",
        f"- **Report Date (UTC):** {report_date.isoformat()}",
        f"- **Window:** {day_start.isoformat()} → {day_end.isoformat()}",
        f"- **Generated At:** {generated_at.isoformat()}",
        f"- **Platform:** Detection Engineering / Cloud-Native Security",
        "",
        "## Executive Summary",
        "",
        f"| Metric | Count |",
        f"| --- | ---: |",
        f"| Total Critical Alerts | {summary['total_critical']} |",
        f"| Open | {summary['open']} |",
        f"| Investigating | {summary['investigating']} |",
        f"| Resolved | {summary['resolved']} |",
        f"| False Positive | {summary['false_positive']} |",
        f"| Linked Detection Rules | {summary['linked_rules']} |",
        "",
    ]

    if not alerts:
        lines.extend(
            [
                "## Alert Details",
                "",
                "_No critical alerts recorded for this reporting period._",
                "",
                "## Recommendations",
                "",
                "- Maintain current detection coverage and continue Supabase Realtime Monitoring.",
                "- Review poc-lab simulation output to validate pipeline health.",
                "",
            ]
        )
        return "\n".join(lines)

    lines.extend(["## Alert Details", ""])
    for index, alert in enumerate(alerts, start=1):
        lines.append(_format_alert_section(index, alert))

    open_count = summary["open"] + summary["investigating"]
    lines.extend(
        [
            "## Recommendations",
            "",
        ]
    )
    if open_count:
        lines.append(
            f"- **Immediate action:** {open_count} critical alert(s) remain open or under investigation."
        )
    lines.extend(
        [
            "- Correlate critical alerts with generated KQL rules in the `rules` table.",
            "- Validate detections against NIST CSF (Detect function) and OWASP control mappings.",
            "- Ensure Supabase Realtime Monitoring subscribers are active for live triage.",
            "",
        ]
    )
    return "\n".join(lines)


def build_json_report(
    alerts: list[dict[str, Any]],
    report_date: date,
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    generated_at = generated_at or datetime.now(timezone.utc)
    day_start, day_end = _day_bounds(report_date)

    return {
        "report_type": "daily_critical_alerts",
        "report_date": report_date.isoformat(),
        "window": {
            "start": day_start.isoformat(),
            "end": day_end.isoformat(),
        },
        "generated_at": generated_at.isoformat(),
        "summary": _build_summary(alerts),
        "alerts": alerts,
    }


class DailyReporter:
    """Generates daily critical alert summaries from Supabase."""

    def __init__(self, output_dir: Path | None = None) -> None:
        self.output_dir = output_dir or config.REPORTS_DIR

    def generate(
        self,
        report_date: date | None = None,
    ) -> DailyReport:
        report_date = report_date or datetime.now(timezone.utc).date()
        logger.info("Generating daily critical alert report for %s", report_date.isoformat())

        try:
            alerts = get_critical_alerts_for_day(report_date)
        except Exception:
            logger.exception("Failed to fetch critical alerts for %s", report_date)
            raise

        generated_at = datetime.now(timezone.utc)
        markdown = build_markdown_report(alerts, report_date, generated_at)
        json_payload = build_json_report(alerts, report_date, generated_at)
        summary = _build_summary(alerts)

        logger.info(
            "Report built: %d critical alert(s), %d open/investigating",
            summary["total_critical"],
            summary["open"] + summary["investigating"],
        )

        return DailyReport(
            report_date=report_date,
            generated_at=generated_at,
            alerts=alerts,
            summary=summary,
            markdown=markdown,
            json_payload=json_payload,
        )

    def save(self, report: DailyReport) -> tuple[Path, Path]:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        stamp = report.report_date.isoformat()

        markdown_path = self.output_dir / f"critical-alerts-{stamp}.md"
        json_path = self.output_dir / f"critical-alerts-{stamp}.json"

        try:
            markdown_path.write_text(report.markdown, encoding="utf-8")
            json_path.write_text(
                json.dumps(report.json_payload, indent=2, default=str),
                encoding="utf-8",
            )
        except OSError:
            logger.exception("Failed to write report files for %s", stamp)
            raise

        logger.info("Report saved: %s, %s", markdown_path, json_path)
        return markdown_path, json_path

    def run(self, report_date: date | None = None) -> DailyReport:
        report = self.generate(report_date)
        self.save(report)
        return report


def main() -> None:
    report_date: date | None = None
    if len(sys.argv) > 1:
        report_date = date.fromisoformat(sys.argv[1])

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    reporter = DailyReporter()
    report = reporter.run(report_date)
    print(report.markdown)


if __name__ == "__main__":
    main()
