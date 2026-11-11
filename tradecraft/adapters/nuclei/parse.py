"""
Pure parsing functions for nuclei scanner output. No I/O or subprocess logic here.
"""
from __future__ import annotations

import json
import urllib.parse
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_SEVERITY_RANK = {sev: idx for idx, sev in enumerate(SEVERITY_ORDER)}


def host_port_from_target(target: str) -> Tuple[str, int]:
    """Extract (host, port) from a target string or URL."""
    parsed = urllib.parse.urlsplit(target if "://" in target else f"//{target}")
    host = parsed.hostname or target
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return host, port


def worst_severity(severities: Iterable[str]) -> Optional[str]:
    """Return the worst (highest priority) severity from a collection of severities."""
    found = [s.lower() for s in severities if s and s.lower() in _SEVERITY_RANK]
    if not found:
        return None
    return min(found, key=lambda s: _SEVERITY_RANK[s])


def parse_nuclei_output(stdout: str) -> Dict[str, Any]:
    """Parses newline-delimited JSON output from nuclei scanner into structured
    findings sorted by severity."""
    findings: List[Dict[str, Any]] = []
    seen: Set[Tuple[str, str]] = set()
    severities_count: Dict[str, int] = {s: 0 for s in SEVERITY_ORDER}

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue

        if not isinstance(data, dict):
            continue

        template_id = data.get("template-id") or data.get("template") or ""
        info = data.get("info", {}) if isinstance(data.get("info"), dict) else {}
        name = info.get("name") or template_id or "Unknown Finding"
        severity = (info.get("severity") or "info").lower()
        if severity not in _SEVERITY_RANK:
            severity = "info"

        matched_at = data.get("matched-at") or data.get("url") or data.get("host") or ""
        dedup_key = (template_id, matched_at)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        type_name = data.get("type", "http")
        classification = info.get("classification", {}) if isinstance(info.get("classification"), dict) else {}
        cve_id = classification.get("cve-id")
        extracted_results = data.get("extracted-results", [])
        description = info.get("description", "")

        finding: Dict[str, Any] = {
            "template_id": template_id,
            "name": name,
            "severity": severity,
            "type": type_name,
            "matched_at": matched_at,
        }
        if cve_id:
            finding["cve_id"] = cve_id
        if extracted_results:
            finding["extracted_results"] = extracted_results
        if description:
            finding["description"] = description

        findings.append(finding)
        severities_count[severity] += 1

    # Sort findings by severity ranking (critical -> high -> medium -> low -> info)
    findings.sort(key=lambda f: _SEVERITY_RANK.get(f.get("severity", "info"), 999))
    worst_sev = worst_severity(f["severity"] for f in findings)

    return {
        "findings": findings,
        "total_findings": len(findings),
        "worst_severity": worst_sev,
        "severities_count": severities_count,
    }
