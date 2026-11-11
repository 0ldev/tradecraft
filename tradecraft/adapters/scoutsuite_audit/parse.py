"""
Parsing logic for scoutsuite_audit: turns ScoutSuite's JS-wrapped JSON
report into a bounded, model-facing list of flagged findings.

Pure functions, no I/O, no subprocess calls.

ScoutSuite writes its report as a JavaScript file whose body is an
assignment, `scoutsuite_results = {...}`, which the bundled HTML report
loads via a script tag. The payload after that prefix is plain JSON, so
the prefix is stripped and the rest parsed with json.loads. Each service
lives under `services.<service>.findings.<rule_id>`, and a rule carries
`level` ("danger" | "warning"), `flagged_items` (count of resources that
violated it), `checked_items`, and `description`.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

MAX_FINDINGS_RETURNED = 100
MAX_ERROR_CHARS = 500
MAX_EVIDENCE_CHARS = 2_000_000
MAX_OUTPUT_TAIL_CHARS = 500

_ASSIGNMENT_PREFIX_REGEX = re.compile(r"^\s*scoutsuite_results\s*=\s*", re.MULTILINE)
_SEVERITY_RANK = {"danger": 0, "warning": 1}


@dataclass
class RawScoutSuiteResult:
    target: str = ""
    provider: str = ""
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    error: Optional[str] = None
    # Contents of the scoutsuite_results_*.js file read from the disposable
    # report directory before it is removed. Empty when none was written.
    report_text: str = ""


def _tail(text: str) -> str:
    lines = [line.strip() for line in (text or "").splitlines() if line.strip()]
    return lines[-1][:MAX_OUTPUT_TAIL_CHARS] if lines else ""


def parse_report_js(report_text: str) -> Optional[Dict[str, Any]]:
    """Strips the `scoutsuite_results = ` assignment prefix and parses the
    JSON payload. Returns None when the text is not a JSON object."""
    if not report_text or not report_text.strip():
        return None
    body = _ASSIGNMENT_PREFIX_REGEX.sub("", report_text, count=1).strip()
    if body.endswith(";"):
        body = body[:-1].rstrip()
    try:
        parsed = json.loads(body)
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None


def extract_error(raw: RawScoutSuiteResult) -> Optional[str]:
    """Returns a hard execution error, or None if scout produced a report.

    A non-zero exit or a missing report is a failure. ScoutSuite's own
    per-service AccessDenied warnings are not: those land in the report
    as skipped resources, and the rest of the audit still counts.
    """
    if raw.error:
        return raw.error[:MAX_ERROR_CHARS]

    if raw.returncode != 0:
        tail = _tail(f"{raw.stderr or ''}\n{raw.stdout or ''}")
        return (
            f"scout exited with code {raw.returncode}"
            + (f": {tail}" if tail else "")
        )[:MAX_ERROR_CHARS]

    if not (raw.report_text or "").strip():
        return "scout produced no report file"

    return None


def _severity_rank(level: Any) -> int:
    return _SEVERITY_RANK.get(str(level or "").lower(), len(_SEVERITY_RANK))


def extract_flagged_findings(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Every rule with flagged_items > 0, across all services, unsorted."""
    findings: List[Dict[str, Any]] = []
    services = report.get("services") or {}
    if not isinstance(services, dict):
        return findings

    for service_name, service in services.items():
        if not isinstance(service, dict):
            continue
        rules = service.get("findings") or {}
        if not isinstance(rules, dict):
            continue
        for rule_id, rule in rules.items():
            if not isinstance(rule, dict):
                continue
            flagged = rule.get("flagged_items") or 0
            if not isinstance(flagged, int) or flagged <= 0:
                continue
            findings.append({
                "service": service_name,
                "rule": rule_id,
                "level": str(rule.get("level") or ""),
                "description": str(rule.get("description") or ""),
                "flagged_items": flagged,
                "checked_items": rule.get("checked_items") or 0,
            })
    return findings


def parse_scoutsuite_result(raw: RawScoutSuiteResult) -> Dict[str, Any]:
    """Turns one raw scoutsuite_audit invocation into the model-facing result.

    The full parsed report is returned under the private key `_report`
    (absent on failure) so the Tool layer can store it as evidence; the
    Tool layer pops that key before the result reaches the model.
    """
    base: Dict[str, Any] = {
        "target": raw.target,
        "provider": raw.provider,
    }

    error = extract_error(raw)
    if error:
        return {**base, "status": "failed", "error": error}

    report = parse_report_js(raw.report_text)
    if report is None:
        return {
            **base,
            "status": "failed",
            "error": "scout report file was not parseable as ScoutSuite results JSON",
        }

    ordered = sorted(
        extract_flagged_findings(report),
        key=lambda f: (_severity_rank(f["level"]), f["service"], f["rule"]),
    )
    total = len(ordered)
    capped = ordered[:MAX_FINDINGS_RETURNED]

    result: Dict[str, Any] = {
        **base,
        "status": "success",
        "total_findings": total,
        "findings": capped,
        "truncated": total > MAX_FINDINGS_RETURNED,
        "_report": report,
    }
    if total == 0:
        result["notes"] = ["scout reported no flagged misconfigurations for the scanned services."]
    return result


def build_full_evidence(target: str, provider: str, report: Dict[str, Any]) -> Dict[str, Any]:
    """Stores the full report dict as evidence, or a bounded JSON text if the
    serialized report exceeds MAX_EVIDENCE_CHARS."""
    serialized = json.dumps(report)
    if len(serialized) <= MAX_EVIDENCE_CHARS:
        return {"target": target, "provider": provider, "report": report}
    return {
        "target": target,
        "provider": provider,
        "report_truncated": True,
        "report_json": serialized[:MAX_EVIDENCE_CHARS],
    }
