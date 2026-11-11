"""
Parsing logic for graphql_authz_probe results. Pure functions, no I/O.
"""
from __future__ import annotations

from typing import Any, Dict, List

from tradecraft.adapters.graphql_authz_probe.execute import GraphqlAuthzResult


def parse(result: GraphqlAuthzResult) -> Dict[str, Any]:
    output: Dict[str, Any] = {
        "target": result.target,
        "vulnerable": result.vulnerable,
        "summary": result.summary,
        "error": result.error,
        "fields_checked": [],
    }

    findings: List[str] = []
    for r in result.fields_checked:
        output["fields_checked"].append({
            "field_name": r.field_name,
            "query": r.query,
            "status": r.status,
            "baseline_resolved": r.baseline_resolved,
            "unauth_resolved": r.unauth_resolved,
            "vulnerable": r.vulnerable,
        })
        if r.vulnerable:
            findings.append(
                f"Query field '{r.field_name}' resolves real data with no authentication (BOLA)"
            )

    output["findings"] = findings
    return output
