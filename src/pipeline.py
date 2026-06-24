"""End-to-end Detection Engineering pipeline orchestrator."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from src.ai_engine import AIEngine, resolve_analysis_mode
from src.database import get_unprocessed_logs, mark_log_analyzed, rule_exists_for_log
from src.log_processor import LogProcessor
from src.logging_config import get_logger
from src.reporter import DailyReporter

import config

logger = get_logger("pipeline")


@dataclass
class PipelineResult:
    logs_ingested: int = 0
    logs_analyzed: int = 0
    rules_created: int = 0
    alerts_created: int = 0
    rules: list[dict[str, Any]] = field(default_factory=list)
    alerts: list[dict[str, Any]] = field(default_factory=list)
    report_path: str | None = None


class Pipeline:
    """Orchestrates ingest → analyze → alert → report."""

    def __init__(self) -> None:
        self.engine = AIEngine()

    def ingest_logs(self, raw_logs: list[dict[str, Any]]) -> int:
        processor = LogProcessor(auto_start=False)
        processor.process_many(raw_logs)
        count = processor.shutdown()
        logger.info("Ingested %d log(s)", count)
        return count

    def analyze_unprocessed(self, limit: int = 50) -> PipelineResult:
        result = PipelineResult()
        logs = get_unprocessed_logs(limit=limit)
        logger.info("Found %d unprocessed log(s)", len(logs))

        for log in logs:
            log_id = str(log.get("id", ""))
            result.logs_analyzed += 1

            if log_id and rule_exists_for_log(log_id):
                logger.info("Skipping already-processed log %s", log_id)
                mark_log_analyzed(log_id)
                continue

            try:
                saved = self.engine.analyze_and_save(log, log_id or None)
            except Exception:
                logger.exception("Analysis failed for log %s", log_id)
                continue

            if saved and saved.get("status") == "created":
                result.rules_created += 1
                result.rules.append(saved["rule"])
                if saved.get("alert"):
                    result.alerts_created += 1
                    result.alerts.append(saved["alert"])

        return result

    def run_report(self) -> str | None:
        reporter = DailyReporter()
        report = reporter.run()
        stamp = report.report_date.isoformat()
        return str(config.REPORTS_DIR / f"critical-alerts-{stamp}.md")

    def run_full(
        self,
        raw_logs: list[dict[str, Any]] | None = None,
        *,
        analyze: bool = True,
        report: bool = False,
        analyze_limit: int = 50,
    ) -> PipelineResult:
        result = PipelineResult()
        logger.info("Pipeline started (mode=%s)", resolve_analysis_mode())

        if raw_logs:
            result.logs_ingested = self.ingest_logs(raw_logs)

        if analyze:
            analysis = self.analyze_unprocessed(limit=analyze_limit)
            result.logs_analyzed = analysis.logs_analyzed
            result.rules_created = analysis.rules_created
            result.alerts_created = analysis.alerts_created
            result.rules = analysis.rules
            result.alerts = analysis.alerts

        if report:
            result.report_path = self.run_report()

        logger.info(
            "Pipeline complete: ingested=%d rules=%d alerts=%d",
            result.logs_ingested,
            result.rules_created,
            result.alerts_created,
        )
        return result
