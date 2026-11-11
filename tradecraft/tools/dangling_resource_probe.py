from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.dangling_resource_probe.execute import execute as run_dangling_probe
from tradecraft.adapters.dangling_resource_probe.parse import parse as parse_dangling
from tradecraft.tools.base import Tool


class DanglingResourceProbe(Tool):
    tool_id = "dangling_resource_probe"

    def run(self, target: str, timeout: int = 10) -> Dict[str, Any]:
        raw = run_dangling_probe(target=target, timeout=timeout)
        parsed = parse_dangling(raw)

        parsed["_full_evidence"] = {
            "target": target,
            "host": parsed.get("host", ""),
            "status_code": raw.status_code,
            "matched_provider": raw.matched_provider,
            "matched_signature": raw.matched_signature,
            "body_snippet": raw.body_snippet,
        }
        return parsed

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        host = result.get("host") or target
        return host, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not result.get("dangling"):
            return []
        fact: Dict[str, Any] = {
            "host": result.get("host") or params.get("target", ""),
            "port": 443,
            "vulnerability": f"Dangling DNS record -- resource unclaimed on {result.get('matched_provider', '')} (subdomain/cloud-resource takeover candidate)",
            "severity": "high",
        }
        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]
        return [fact]
