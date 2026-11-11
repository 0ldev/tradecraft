"""
Parsing logic for trivy_scan: turns trivy's JSON report into a bounded,
model-facing list of vulnerabilities.

Pure functions, no I/O, no subprocess calls.

`trivy image --format json` writes a document with `Results`, a list of
per-target entries (for a container image: one OS-package entry plus one
entry per language-package file found). Each entry may carry a
`Vulnerabilities` list; an entry with no findings omits that key or leaves
it empty. Each vulnerability carries `VulnerabilityID`, `PkgName`,
`InstalledVersion`, `FixedVersion` (empty when no fix exists),
`Severity` (UNKNOWN | LOW | MEDIUM | HIGH | CRITICAL), `Title`, and
`PrimaryURL`.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

MAX_FINDINGS_RETURNED = 100
MAX_ERROR_CHARS = 500
MAX_EVIDENCE_CHARS = 2_000_000
MAX_OUTPUT_TAIL_CHARS = 500
MAX_TITLE_CHARS = 300

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
_SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}


@dataclass
class RawTrivyResult:
    target: str = ""
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    error: Optional[str] = None
    # Contents of the JSON report trivy wrote to its --output path before the
    # disposable directory is removed. Empty when none was written.
    report_text: str = ""


def _tail(text: str) -> str:
    lines = [line.strip() for line in (text or "").splitlines() if line.strip()]
    return lines[-1][:MAX_OUTPUT_TAIL_CHARS] if lines else ""


def parse_report_json(report_text: str) -> Optional[Dict[str, Any]]:
    """Parses trivy's JSON report. Returns None when the text is not a JSON
    object."""
    if not report_text or not report_text.strip():
        return None
    try:
        parsed = json.loads(report_text)
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None


def extract_error(raw: RawTrivyResult) -> Optional[str]:
    """Returns a hard execution error, or None if trivy produced a report.

    A non-zero exit or a missing report is a failure. A successful scan with
    zero vulnerabilities is not an error.
    """
    if raw.error:
        return raw.error[:MAX_ERROR_CHARS]

    if raw.returncode != 0:
        tail = _tail(f"{raw.stderr or ''}\n{raw.stdout or ''}")
        return (
            f"trivy exited with code {raw.returncode}"
            + (f": {tail}" if tail else "")
        )[:MAX_ERROR_CHARS]

    if not (raw.report_text or "").strip():
        return "trivy produced no report file"

    return None


def _severity_rank(severity: Any) -> int:
    return _SEVERITY_RANK.get(str(severity or "").upper(), len(SEVERITIES))


def extract_vulnerabilities(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Every vulnerability across all Results entries, unsorted."""
    findings: List[Dict[str, Any]] = []
    results = report.get("Results") or []
    if not isinstance(results, list):
        return findings

    for entry in results:
        if not isinstance(entry, dict):
            continue
        vulns = entry.get("Vulnerabilities") or []
        if not isinstance(vulns, list):
            continue
        for vuln in vulns:
            if not isinstance(vuln, dict):
                continue
            findings.append({
                "vulnerability_id": str(vuln.get("VulnerabilityID") or ""),
                "package": str(vuln.get("PkgName") or ""),
                "installed_version": str(vuln.get("InstalledVersion") or ""),
                "fixed_version": str(vuln.get("FixedVersion") or ""),
                "severity": str(vuln.get("Severity") or "UNKNOWN").upper(),
                "title": str(vuln.get("Title") or "")[:MAX_TITLE_CHARS],
                "url": str(vuln.get("PrimaryURL") or ""),
                "result_target": str(entry.get("Target") or ""),
            })
    return findings


def parse_trivy_result(raw: RawTrivyResult) -> Dict[str, Any]:
    """Turns one raw trivy_scan invocation into the model-facing result.

    The full parsed report is returned under the private key `_report`
    (absent on failure) so the Tool layer can store it as evidence; the
    Tool layer pops that key before the result reaches the model.
    """
    base: Dict[str, Any] = {"target": raw.target}

    error = extract_error(raw)
    if error:
        return {**base, "status": "failed", "error": error}

    report = parse_report_json(raw.report_text)
    if report is None:
        return {
            **base,
            "status": "failed",
            "error": "trivy report file was not parseable as JSON",
        }

    ordered = sorted(
        extract_vulnerabilities(report),
        key=lambda f: (_severity_rank(f["severity"]), f["package"], f["vulnerability_id"]),
    )
    total = len(ordered)
    severity_counts: Dict[str, int] = {name: 0 for name in SEVERITIES}
    for finding in ordered:
        severity_counts[finding["severity"] if finding["severity"] in severity_counts else "UNKNOWN"] += 1

    result: Dict[str, Any] = {
        **base,
        "status": "success",
        "total_findings": total,
        "severity_counts": severity_counts,
        "findings": ordered[:MAX_FINDINGS_RETURNED],
        "truncated": total > MAX_FINDINGS_RETURNED,
        "_report": report,
    }
    if total == 0:
        result["notes"] = ["trivy reported no known vulnerabilities for this image's OS and language packages."]
    return result


def build_full_evidence(target: str, report: Dict[str, Any]) -> Dict[str, Any]:
    """Stores the full report dict as evidence, or a bounded JSON text if the
    serialized report exceeds MAX_EVIDENCE_CHARS."""
    serialized = json.dumps(report)
    if len(serialized) <= MAX_EVIDENCE_CHARS:
        return {"target": target, "report": report}
    return {
        "target": target,
        "report_truncated": True,
        "report_json": serialized[:MAX_EVIDENCE_CHARS],
    }
