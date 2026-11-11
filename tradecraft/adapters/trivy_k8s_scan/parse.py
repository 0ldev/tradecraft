"""
Parsing logic for trivy_k8s_scan: turns `trivy k8s --report all --format json`
output into two bounded, model-facing lists -- Kubernetes misconfigurations
and per-image CVEs.

Pure functions, no I/O, no subprocess calls.

Report layout (Trivy's documented `k8s` JSON output): top-level
`ClusterName`, plus `Vulnerabilities` and `Misconfigurations`, each a list of
per-resource objects carrying `Namespace`, `Kind`, `Name`, and `Results`.
Each result entry has `Target`, `Class`, `Type`, and may carry a
`Vulnerabilities` list (CVE rows: `VulnerabilityID`, `PkgName`,
`InstalledVersion`, `FixedVersion`, `Severity`, `Title`, `PrimaryURL`) and/or
a `Misconfigurations` list (check rows: `ID`, `Title`, `Message`, `Severity`,
`Status`, `PrimaryURL`). Both shapes are read defensively: a missing key or a
wrong type yields no rows, never an exception.

Only failing misconfiguration checks are reported. A check whose `Status` is
present and not `FAIL` is a pass and is skipped.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

MAX_FINDINGS_RETURNED = 100
MAX_ERROR_CHARS = 500
MAX_EVIDENCE_CHARS = 2_000_000
MAX_OUTPUT_TAIL_CHARS = 500
MAX_TITLE_CHARS = 300
MAX_MESSAGE_CHARS = 500

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
_SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}


@dataclass
class RawTrivyK8sResult:
    kubeconfig: str = ""
    namespace: str = ""
    context: str = ""
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


def extract_error(raw: RawTrivyK8sResult) -> Optional[str]:
    """Returns a hard execution error, or None if trivy produced a report.

    A non-zero exit or a missing report is a failure. A clean cluster with
    zero findings is not an error.
    """
    if raw.error:
        return raw.error[:MAX_ERROR_CHARS]

    if raw.returncode != 0:
        tail = _tail(f"{raw.stderr or ''}\n{raw.stdout or ''}")
        return (
            f"trivy k8s exited with code {raw.returncode}"
            + (f": {tail}" if tail else "")
        )[:MAX_ERROR_CHARS]

    if not (raw.report_text or "").strip():
        return "trivy k8s produced no report file"

    return None


def _severity_rank(severity: Any) -> int:
    return _SEVERITY_RANK.get(str(severity or "").upper(), len(SEVERITIES))


def _normalize_severity(severity: Any) -> str:
    value = str(severity or "UNKNOWN").upper()
    return value if value in _SEVERITY_RANK else "UNKNOWN"


def _as_list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def _resource_fields(entry: Dict[str, Any]) -> Dict[str, str]:
    return {
        "resource_kind": str(entry.get("Kind") or ""),
        "resource_name": str(entry.get("Name") or ""),
        "namespace": str(entry.get("Namespace") or ""),
    }


def _iter_resource_results(report: Dict[str, Any], section: str):
    """Yields (resource_entry, result_entry) pairs for one top-level section
    ("Vulnerabilities" or "Misconfigurations") of the report."""
    for resource in _as_list(report.get(section)):
        if not isinstance(resource, dict):
            continue
        for result in _as_list(resource.get("Results")):
            if isinstance(result, dict):
                yield resource, result


def extract_vulnerabilities(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Every CVE row across all resources and result entries, unsorted."""
    findings: List[Dict[str, Any]] = []
    for resource, result in _iter_resource_results(report, "Vulnerabilities"):
        for vuln in _as_list(result.get("Vulnerabilities")):
            if not isinstance(vuln, dict):
                continue
            findings.append({
                **_resource_fields(resource),
                "image_target": str(result.get("Target") or ""),
                "vulnerability_id": str(vuln.get("VulnerabilityID") or ""),
                "package": str(vuln.get("PkgName") or ""),
                "installed_version": str(vuln.get("InstalledVersion") or ""),
                "fixed_version": str(vuln.get("FixedVersion") or ""),
                "severity": _normalize_severity(vuln.get("Severity")),
                "title": str(vuln.get("Title") or "")[:MAX_TITLE_CHARS],
                "url": str(vuln.get("PrimaryURL") or ""),
            })
    return findings


def _is_failing_check(check: Dict[str, Any]) -> bool:
    status = check.get("Status")
    if status is None or status == "":
        return True
    return str(status).upper() == "FAIL"


def extract_misconfigurations(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Every failing misconfiguration check across all resources, unsorted."""
    findings: List[Dict[str, Any]] = []
    for resource, result in _iter_resource_results(report, "Misconfigurations"):
        for check in _as_list(result.get("Misconfigurations")):
            if not isinstance(check, dict) or not _is_failing_check(check):
                continue
            findings.append({
                **_resource_fields(resource),
                "check_id": str(check.get("ID") or check.get("AVDID") or ""),
                "severity": _normalize_severity(check.get("Severity")),
                "title": str(check.get("Title") or "")[:MAX_TITLE_CHARS],
                "message": str(check.get("Message") or "")[:MAX_MESSAGE_CHARS],
                "url": str(check.get("PrimaryURL") or ""),
            })
    return findings


def _sort_key(finding: Dict[str, Any], id_field: str) -> Tuple[int, str, str, str]:
    return (
        _severity_rank(finding["severity"]),
        finding["namespace"],
        finding["resource_kind"] + "/" + finding["resource_name"],
        finding[id_field],
    )


def _severity_counts(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {name: 0 for name in SEVERITIES}
    for finding in findings:
        counts[finding["severity"]] += 1
    return counts


def parse_trivy_k8s_result(raw: RawTrivyK8sResult) -> Dict[str, Any]:
    """Turns one raw trivy_k8s_scan invocation into the model-facing result.

    The full parsed report is returned under the private key `_report`
    (absent on failure) so the Tool layer can store it as evidence; the Tool
    layer pops that key before the result reaches the model.
    """
    base: Dict[str, Any] = {
        "kubeconfig": raw.kubeconfig,
        "namespace": raw.namespace or "all",
        "context": raw.context or "default",
    }

    error = extract_error(raw)
    if error:
        return {**base, "status": "failed", "error": error}

    report = parse_report_json(raw.report_text)
    if report is None:
        return {
            **base,
            "status": "failed",
            "error": "trivy k8s report file was not parseable as JSON",
        }

    misconfigs = sorted(
        extract_misconfigurations(report),
        key=lambda f: _sort_key(f, "check_id"),
    )
    cves = sorted(
        extract_vulnerabilities(report),
        key=lambda f: _sort_key(f, "vulnerability_id"),
    )

    result: Dict[str, Any] = {
        **base,
        "status": "success",
        "cluster": str(report.get("ClusterName") or ""),
        "total_misconfigurations": len(misconfigs),
        "misconfiguration_severity_counts": _severity_counts(misconfigs),
        "misconfigurations": misconfigs[:MAX_FINDINGS_RETURNED],
        "misconfigurations_truncated": len(misconfigs) > MAX_FINDINGS_RETURNED,
        "total_vulnerabilities": len(cves),
        "vulnerability_severity_counts": _severity_counts(cves),
        "vulnerabilities": cves[:MAX_FINDINGS_RETURNED],
        "vulnerabilities_truncated": len(cves) > MAX_FINDINGS_RETURNED,
        "_report": report,
    }
    if not misconfigs and not cves:
        result["notes"] = ["trivy k8s reported no misconfigurations and no known vulnerabilities in scope."]
    return result


def build_full_evidence(scope_key: str, report: Dict[str, Any]) -> Dict[str, Any]:
    """Stores the full report dict as evidence, or a bounded JSON text if the
    serialized report exceeds MAX_EVIDENCE_CHARS."""
    serialized = json.dumps(report)
    if len(serialized) <= MAX_EVIDENCE_CHARS:
        return {"scope": scope_key, "report": report}
    return {
        "scope": scope_key,
        "report_truncated": True,
        "report_json": serialized[:MAX_EVIDENCE_CHARS],
    }
