"""
The stack-agnostic counterpart to php_lfi (tradecraft/tools/php_lfi.py), which is
PHP-specific. Classified as destructive: false (confirmation-only read probe,
same as php_lfi) -- the follow-up file harvest reuses the exact same
single-GET read mechanism the confirmation itself already proved, so it
carries no new risk tier.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.http_request.parse import evidence_target_from_url, host_port_from_url
from tradecraft.adapters.path_traversal_probe.execute import execute as trav_execute
from tradecraft.tools.base import Tool


class PathTraversalProbe(Tool):
    tool_id = "path_traversal_probe"

    def run(self, target: str, parameter: str, timeout: int = 15) -> Dict[str, Any]:
        raw = trav_execute(target=target, parameter=parameter, timeout=timeout)
        confirmed = next((p for p in raw.probes if p.confirmed), None)

        result: Dict[str, Any] = {
            "target": raw.target,
            "parameter": raw.parameter,
            "tested_count": raw.tested_count,
            "vulnerable": confirmed is not None,
            "error": raw.error,
        }
        if confirmed:
            result["confirmed_payload"] = confirmed.payload
            result["confirmed_file"] = confirmed.file_description
            result["confirmed_url"] = confirmed.url

            harvested = [p.file_description for p in raw.followup_probes if p.confirmed]
            result["harvested_files"] = harvested
            result["harvested_count"] = len(harvested)

        result["_full_evidence"] = {
            "target": raw.target,
            "parameter": raw.parameter,
            "probes": [_probe_to_dict(p) for p in raw.probes],
            "followup_probes": [_probe_to_dict(p) for p in raw.followup_probes],
        }
        return result

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        return evidence_target_from_url(target) or target, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not result.get("vulnerable"):
            return []
        host, port = host_port_from_url(params.get("target", ""))
        fact: Dict[str, Any] = {
            "host": host,
            "port": port,
            "vulnerability": (
                f"Path Traversal / LFI confirmed via parameter '{params.get('parameter', '')}' "
                f"({result.get('confirmed_file', '')})"
            ),
            "severity": "high",
        }
        harvested_count = result.get("harvested_count", 0)
        if harvested_count:
            fact["harvested_files_count"] = harvested_count
            fact["severity"] = "critical"
        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]
        return [fact]


def _probe_to_dict(p: Any) -> Dict[str, Any]:
    return {
        "payload": p.payload,
        "file_description": p.file_description,
        "status_code": p.status_code,
        "url": p.url,
        "body": p.body,
        "error": p.error,
    }
