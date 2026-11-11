"""
Pure parsing functions for ai_stack_probe output.
Transforms RawAiStackProbeResult into structured findings.
"""
from __future__ import annotations

from typing import Any, Dict, List

from tradecraft.adapters.ai_stack_probe.execute import RawAiStackProbeResult


def parse_probe_result(raw: RawAiStackProbeResult) -> Dict[str, Any]:
    """Parses RawAiStackProbeResult into a normalized dictionary."""
    if raw.error:
        return {
            "target": raw.target,
            "host": raw.host,
            "vulnerable": False,
            "findings": [],
            "count": 0,
            "unauthenticated_count": 0,
            "error": raw.error,
        }

    findings_list: List[Dict[str, Any]] = []
    for f in raw.findings:
        findings_list.append(
            {
                "service": f.service,
                "port": f.port,
                "accessible": f.accessible,
                "unauthenticated": f.unauthenticated,
                "version": f.version,
                "summary": f.summary,
                "details": f.details,
                "error": f.error,
            }
        )

    unauthenticated_count = sum(1 for f in findings_list if f.get("unauthenticated"))
    return {
        "target": raw.target,
        "host": raw.host,
        "vulnerable": raw.vulnerable or (unauthenticated_count > 0),
        "findings": findings_list,
        "count": len(findings_list),
        "unauthenticated_count": unauthenticated_count,
    }
