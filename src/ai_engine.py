"""LLM-powered detection engine using the Cursor SDK."""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import config
from cursor_sdk import Agent, AgentOptions, CursorAgentError, LocalAgentOptions

from src.database import (
    get_alert_by_log_id,
    get_log_by_id,
    get_logs,
    get_rule_for_log,
    get_unprocessed_logs,
    insert_rule,
    mark_log_analyzed,
    rule_exists_for_log,
)
from src.alert_engine import create_alert_for_rule
from src.logging_config import get_logger

logger = get_logger("ai_engine")

VALID_SEVERITIES = frozenset({"low", "medium", "high", "critical"})

_JSON_BLOCK_PATTERN = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)


@dataclass
class ThreatAnalysis:
    threat_detected: bool
    threat_name: str
    description: str
    severity: str
    kql_query: str
    standard: str
    tags: list[str]
    nist_controls: list[str]
    owasp_categories: list[str]
    mitre_techniques: list[str]
    raw_response: dict[str, Any]


def build_analysis_prompt(log: dict[str, Any]) -> str:
    log_json = json.dumps(log, indent=2, default=str)
    return f"""You are a senior detection engineer. Analyze the following processed security log
from an attack simulation lab (poc-lab) and determine whether it indicates a real threat.

Respond with ONLY a valid JSON object (no markdown, no commentary) using this schema:
{{
  "threat_detected": boolean,
  "threat_name": "short rule title",
  "description": "what was detected and why it matters",
  "severity": "low|medium|high|critical",
  "kql_query": "Microsoft Sentinel / Azure Monitor KQL detection query",
  "nist_controls": ["DE.AE", "PR.DS-1"],
  "owasp_categories": ["A01:2021", "A07:2021"],
  "mitre_techniques": ["T1059", "T1021"],
  "tags": ["execution", "lateral-movement"]
}}

Rules:
- Map findings to NIST Cybersecurity Framework (CSF) and OWASP Top 10 where applicable.
- The KQL query must be syntactically valid and reference realistic table/column names.
- If no meaningful threat is present, set threat_detected to false and leave other strings empty.
- Use MITRE ATT&CK technique IDs when relevant.

Log payload:
{log_json}
"""


def parse_llm_response(text: str) -> dict[str, Any]:
    stripped = text.strip()
    block_match = _JSON_BLOCK_PATTERN.search(stripped)
    if block_match:
        stripped = block_match.group(1)

    start = stripped.find("{")
    end = stripped.rfind("}")
    if start == -1 or end == -1:
        raise ValueError("LLM response does not contain JSON.")

    return json.loads(stripped[start : end + 1])


def format_standard(
    nist_controls: list[str],
    owasp_categories: list[str],
    mitre_techniques: list[str],
) -> str:
    parts: list[str] = []
    parts.extend(f"NIST:{control}" for control in nist_controls)
    parts.extend(f"OWASP:{category}" for category in owasp_categories)
    parts.extend(f"MITRE:{technique}" for technique in mitre_techniques)
    return "; ".join(parts)


def _normalize_string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _normalize_severity(value: Any) -> str:
    severity = str(value or "medium").lower().strip()
    if severity not in VALID_SEVERITIES:
        return "medium"
    return severity


def to_threat_analysis(payload: dict[str, Any]) -> ThreatAnalysis:
    nist_controls = _normalize_string_list(payload.get("nist_controls"))
    owasp_categories = _normalize_string_list(payload.get("owasp_categories"))
    mitre_techniques = _normalize_string_list(payload.get("mitre_techniques"))

    standard = str(payload.get("standard") or "").strip()
    if not standard:
        standard = format_standard(nist_controls, owasp_categories, mitre_techniques)

    return ThreatAnalysis(
        threat_detected=bool(payload.get("threat_detected")),
        threat_name=str(payload.get("threat_name") or "Untitled Detection").strip(),
        description=str(payload.get("description") or "").strip(),
        severity=_normalize_severity(payload.get("severity")),
        kql_query=str(payload.get("kql_query") or "").strip(),
        standard=standard,
        tags=_normalize_string_list(payload.get("tags")),
        nist_controls=nist_controls,
        owasp_categories=owasp_categories,
        mitre_techniques=mitre_techniques,
        raw_response=payload,
    )


_THREAT_PATTERNS: list[tuple[str, str, str, list[str], list[str], list[str]]] = [
    (
        "credential",
        "Suspicious Credential Access",
        "high",
        ["DE.AE", "PR.AC-1"],
        ["A07:2021"],
        ["T1003"],
    ),
    (
        "lateral",
        "Lateral Movement Detected",
        "high",
        ["DE.AE", "RS.AN-1"],
        ["A01:2021"],
        ["T1021"],
    ),
    (
        "powershell",
        "Suspicious PowerShell Execution",
        "medium",
        ["DE.CM", "PR.PT-1"],
        ["A03:2021"],
        ["T1059.001"],
    ),
    (
        "execution",
        "Suspicious Execution Activity",
        "medium",
        ["DE.AE", "DE.CM-1"],
        ["A03:2021"],
        ["T1059"],
    ),
    (
        "exfil",
        "Potential Data Exfiltration",
        "critical",
        ["DE.AE", "PR.DS-1"],
        ["A02:2021"],
        ["T1041"],
    ),
]


def resolve_analysis_mode() -> str:
    mode = (config.AI_ANALYSIS_MODE or "auto").lower().strip()
    if mode == "auto":
        return "cursor" if config.CURSOR_API_KEY else "heuristic"
    if mode not in {"cursor", "heuristic"}:
        logger.warning("Unknown AI_ANALYSIS_MODE=%s, falling back to auto", mode)
        return "cursor" if config.CURSOR_API_KEY else "heuristic"
    if mode == "cursor" and not config.CURSOR_API_KEY:
        logger.warning("AI_ANALYSIS_MODE=cursor but CURSOR_API_KEY missing; using heuristic")
        return "heuristic"
    return mode


def analyze_log_heuristic(log: dict[str, Any]) -> ThreatAnalysis:
    """Rule-based fallback when Cursor API key is unavailable."""
    log_id = log.get("id", "unknown")
    logger.info("Running heuristic analysis for log %s", log_id)

    event_type = str(log.get("event_type") or "").lower()
    source = str(log.get("source") or "").lower()
    hostname = str(log.get("hostname") or "unknown")
    username = str(log.get("username") or "unknown")
    raw_data = log.get("raw_data") or {}
    raw_text = json.dumps(raw_data, default=str).lower()
    haystack = f"{event_type} {source} {raw_text}"

    matched = None
    for keyword, name, severity, nist, owasp, mitre in _THREAT_PATTERNS:
        if keyword in haystack:
            matched = (name, severity, nist, owasp, mitre, keyword)
            break

    if not matched and event_type not in {"", "test", "test_batch", "info"}:
        matched = (
            "Anomalous Lab Event",
            "medium",
            ["DE.AE"],
            ["A09:2021"],
            ["T1078"],
            event_type or "unknown",
        )

    if not matched:
        payload = {
            "threat_detected": False,
            "threat_name": "",
            "description": "",
            "severity": "low",
            "kql_query": "",
            "nist_controls": [],
            "owasp_categories": [],
            "mitre_techniques": [],
            "tags": [],
            "engine": "heuristic",
        }
        return to_threat_analysis(payload)

    name, severity, nist, owasp, mitre, keyword = matched
    technique = raw_data.get("technique", mitre[0] if mitre else "T0000")

    kql_query = f"""SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID in (4688, 4624, 4625, 4648)
| where Computer has "{hostname}" or Account has "{username}"
| where Process has "{keyword}" or CommandLine has "{keyword}"
| project TimeGenerated, Computer, Account, EventID, Process, CommandLine
| order by TimeGenerated desc"""

    payload = {
        "threat_detected": True,
        "threat_name": name,
        "description": (
            f"Heuristic detection for '{keyword}' activity from source '{source or 'poc-lab'}' "
            f"on host '{hostname}' by user '{username}'. MITRE reference: {technique}."
        ),
        "severity": severity,
        "kql_query": kql_query.strip(),
        "nist_controls": nist,
        "owasp_categories": owasp,
        "mitre_techniques": mitre,
        "tags": [keyword, "heuristic", "poc-lab"],
        "engine": "heuristic",
    }
    analysis = to_threat_analysis(payload)
    logger.info(
        "Heuristic analysis complete for log %s: threat_detected=%s",
        log_id,
        analysis.threat_detected,
    )
    return analysis


_llm_disabled: bool = False


def analyze_log(
    log: dict[str, Any],
    *,
    api_key: str | None = None,
    model: str | None = None,
    mode: str | None = None,
) -> ThreatAnalysis:
    global _llm_disabled
    selected_mode = mode or resolve_analysis_mode()
    if selected_mode == "heuristic" or _llm_disabled:
        return analyze_log_heuristic(log)

    try:
        return analyze_log_with_llm(log, api_key=api_key, model=model)
    except (RuntimeError, CursorAgentError, OSError) as exc:
        _llm_disabled = True
        logger.warning("Cursor LLM unavailable (%s); using heuristic fallback", exc)
        return analyze_log_heuristic(log)


def analyze_log_with_llm(
    log: dict[str, Any],
    *,
    api_key: str | None = None,
    model: str | None = None,
) -> ThreatAnalysis:
    key = api_key or config.CURSOR_API_KEY
    if not key:
        logger.error("CURSOR_API_KEY is not configured")
        raise ValueError(
            "CURSOR_API_KEY is not set. Add it to .env "
            "(Cursor Dashboard > Integrations)."
        )

    log_id = log.get("id", "unknown")
    logger.info("Starting LLM analysis for log %s", log_id)

    prompt = build_analysis_prompt(log)
    project_root = str(Path(config.BASE_DIR))

    try:
        result = Agent.prompt(
            prompt,
            AgentOptions(
                api_key=key,
                model=model or config.CURSOR_MODEL,
                local=LocalAgentOptions(cwd=project_root),
            ),
        )
    except CursorAgentError as exc:
        logger.exception("Cursor agent startup failed for log %s", log_id)
        raise RuntimeError(f"Cursor agent failed to start: {exc.message}") from exc

    if result.status == "error":
        logger.error("Cursor analysis run failed: %s (log=%s)", result.id, log_id)
        raise RuntimeError(f"Cursor analysis run failed: {result.id}")

    response_text = result.result or ""
    if not response_text.strip():
        raise RuntimeError("Cursor returned an empty analysis response.")

    payload = parse_llm_response(response_text)
    analysis = to_threat_analysis(payload)
    logger.info(
        "Analysis complete for log %s: threat_detected=%s, severity=%s",
        log_id,
        analysis.threat_detected,
        analysis.severity,
    )
    return analysis


def build_rule_payload(
    analysis: ThreatAnalysis,
    log_id: str | None = None,
) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "nist_controls": analysis.nist_controls,
        "owasp_categories": analysis.owasp_categories,
        "mitre_techniques": analysis.mitre_techniques,
        "llm_analysis": analysis.raw_response,
    }
    if log_id:
        metadata["source_log_id"] = log_id

    return {
        "name": analysis.threat_name,
        "description": analysis.description,
        "rule_type": "kql",
        "content": analysis.kql_query,
        "severity": analysis.severity,
        "standard": analysis.standard,
        "enabled": True,
        "tags": analysis.tags,
        "metadata": metadata,
    }


class AIEngine:
    """Fetches logs from Supabase, analyzes them with Cursor, and persists rules."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
    ) -> None:
        self.api_key = api_key
        self.model = model

    def analyze(self, log: dict[str, Any]) -> ThreatAnalysis | None:
        analysis = analyze_log(
            log,
            api_key=self.api_key,
            model=self.model,
        )
        if not analysis.threat_detected:
            return None
        if not analysis.kql_query:
            raise ValueError("Threat detected but KQL query is missing from LLM output.")
        return analysis

    def analyze_and_save(
        self,
        log: dict[str, Any],
        log_id: str | None = None,
    ) -> dict[str, Any] | None:
        resolved_log_id = str(log_id or log.get("id") or "")

        if resolved_log_id and rule_exists_for_log(resolved_log_id):
            logger.info("Rule already exists for log %s; skipping", resolved_log_id)
            mark_log_analyzed(resolved_log_id)
            existing_rule = get_rule_for_log(resolved_log_id)
            existing_alert = get_alert_by_log_id(resolved_log_id) if existing_rule else None
            return {
                "status": "already_exists",
                "rule": existing_rule,
                "alert": existing_alert,
            }

        analysis = self.analyze(log)
        if analysis is None:
            logger.info("No threat detected; skipping rule creation")
            if resolved_log_id:
                mark_log_analyzed(resolved_log_id)
            return {"status": "no_threat", "rule": None, "alert": None}

        payload = build_rule_payload(analysis, resolved_log_id or None)
        rule = insert_rule(payload)
        logger.info("Rule persisted: %s (%s)", rule.get("name"), rule.get("id"))

        engine_name = resolve_analysis_mode()
        raw_engine = analysis.raw_response.get("engine", engine_name)
        alert = create_alert_for_rule(
            rule,
            resolved_log_id or None,
            analysis_engine=str(raw_engine),
        )

        if resolved_log_id:
            mark_log_analyzed(resolved_log_id)

        return {"status": "created", "rule": rule, "alert": alert}

    def analyze_log_by_id(self, log_id: str) -> dict[str, Any] | None:
        log = get_log_by_id(log_id)
        if log is None:
            logger.warning("Log not found: %s", log_id)
            raise ValueError(f"Log not found: {log_id}")
        return self.analyze_and_save(log, log_id)

    def analyze_recent_logs(self, limit: int = 10) -> list[dict[str, Any]]:
        saved: list[dict[str, Any]] = []
        for log in get_unprocessed_logs(limit=limit):
            result = self.analyze_and_save(log, log.get("id"))
            if result and result.get("status") == "created":
                saved.append(result)
        return saved


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python -m src.ai_engine <log_id>", file=sys.stderr)
        sys.exit(1)

    log_id = sys.argv[1]
    try:
        engine = AIEngine()
        rule = engine.analyze_log_by_id(log_id)
    except Exception:
        logger.exception("CLI analysis failed for log %s", log_id)
        sys.exit(1)

    if rule is None:
        print("No threat detected; rule not created.")
        return

    if rule.get("status") == "already_exists":
        rule_data = rule.get("rule") or {}
        print(f"Rule already exists: {rule_data.get('name', '—')} ({rule_data.get('id', '—')})")
        return

    if rule.get("status") == "no_threat":
        print("No threat detected; rule not created.")
        return

    rule_data = rule.get("rule", rule)
    alert_data = rule.get("alert")
    print(f"Rule created: {rule_data['name']} ({rule_data['id']})")
    print(f"Standard: {rule_data.get('standard', '')}")
    if alert_data:
        print(f"Alert created: {alert_data['title']} ({alert_data['id']})")


if __name__ == "__main__":
    main()
