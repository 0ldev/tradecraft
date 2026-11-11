from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.subzy import execute as subzy_execute
from tradecraft.adapters.subzy import parse as subzy_parse
from tradecraft.tools.base import Tool


class Subzy(Tool):
    tool_id = "subzy"

    def run(self, target: str, concurrency: int = 10) -> Dict[str, Any]:
        raw = subzy_execute.execute(target=target, concurrency=concurrency)
        if raw.error:
            return {"target": target, "vulnerable": [], "error": raw.error}

        findings = subzy_parse.parse_subzy_output(raw.stdout)
        res: Dict[str, Any] = {
            "target": target,
            "vulnerable_count": len(findings),
            "vulnerable": findings,
        }

        res["_full_evidence"] = {
            "target": target,
            "vulnerable_count": len(findings),
            "vulnerable": findings,
        }
        return res

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any, List[str]] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        hosts = subzy_execute.normalize_targets(target)
        canonical_target = hosts[0] if hosts else target
        return canonical_target, full, hosts[1:]

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        findings = result.get("vulnerable", [])
        facts: List[Dict[str, Any]] = []

        for entry in findings:
            sub = entry.get("subdomain")
            service = entry.get("service", "Unknown")
            if not sub:
                continue

            fact: Dict[str, Any] = {
                "host": sub,
                "port": 443,
                "subdomain_takeover": service,
            }
            if result.get("evidence_id"):
                fact["evidence"] = result["evidence_id"]
            facts.append(fact)

        return facts
