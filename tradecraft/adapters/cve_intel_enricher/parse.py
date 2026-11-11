"""
Pure parsing functions for cve_intel_enricher output.
Transforms RawCveIntelResult into structured intelligence findings.
"""
from __future__ import annotations

from typing import Any, Dict, List

from tradecraft.adapters.cve_intel_enricher.execute import RawCveIntelResult


def parse_cve_intel(raw: RawCveIntelResult) -> Dict[str, Any]:
    """Transforms RawCveIntelResult into normalized dictionary."""
    if raw.error:
        return {
            "cves_requested": raw.cves_requested,
            "total_evaluated": 0,
            "critical_count": 0,
            "high_count": 0,
            "kev_count": 0,
            "ai_stack_count": 0,
            "entries": [],
            "error": raw.error,
        }

    entries_list: List[Dict[str, Any]] = []
    critical_count = 0
    high_count = 0
    kev_count = 0
    ai_stack_count = 0

    for e in raw.entries:
        if e.in_kev:
            kev_count += 1
        if e.is_ai_stack:
            ai_stack_count += 1
        if e.priority == "CRITICAL":
            critical_count += 1
        elif e.priority == "HIGH":
            high_count += 1

        entries_list.append(
            {
                "cve": e.cve,
                "priority": e.priority,
                "in_kev": e.in_kev,
                "epss_score": e.epss_score,
                "epss_percentile": e.epss_percentile,
                "is_ai_stack": e.is_ai_stack,
                "summary": e.summary,
                "vulnerability_name": e.kev_vulnerability_name,
                "date_added_to_kev": e.kev_date_added,
                "required_action": e.kev_required_action,
            }
        )

    # Sort entries by priority: CRITICAL > HIGH > MEDIUM > LOW, then by EPSS descending
    priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    entries_list.sort(
        key=lambda x: (
            priority_order.get(x["priority"], 4),
            -(x["epss_score"] or 0.0),
        )
    )

    return {
        "cves_requested": raw.cves_requested,
        "total_evaluated": len(entries_list),
        "critical_count": critical_count,
        "high_count": high_count,
        "kev_count": kev_count,
        "ai_stack_count": ai_stack_count,
        "sources": raw.sources,
        "entries": entries_list,
    }
