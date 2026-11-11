"""
Differential NoSQL operator injection probing of a JSON body field.
Non-destructive; reports anomalous response shapes only and never claims
an auth bypass.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from tradecraft.adapters.http_request.parse import evidence_target_from_url, host_port_from_url
from tradecraft.adapters.nosql_injection_probe import execute as nosql_execute
from tradecraft.adapters.nosql_injection_probe import parse as nosql_parse
from tradecraft.tools.base import Tool


class NosqlInjectionProbe(Tool):
    tool_id = "nosql_injection_probe"

    def run(
        self,
        target: str,
        body: str,
        field: str,
        headers: Optional[str] = None,
        timeout: int = 10,
    ) -> Dict[str, Any]:
        raw = nosql_execute.execute(
            target=target,
            body=body,
            field=field,
            headers=headers,
            timeout=timeout,
        )
        parsed = nosql_parse.parse(raw)

        # Store complete evidence outside prompt context
        parsed["_full_evidence"] = {
            "target": raw.target,
            "field": raw.field,
            "baseline": {
                "status_code": raw.baseline_response.status_code if raw.baseline_response else 0,
                "body": raw.baseline_response.body if raw.baseline_response else "",
            },
            "probes": [
                {
                    "operator": p.operator,
                    "status_code": p.status_code,
                    "body": p.body,
                }
                for p in raw.probes
            ],
        }

        return parsed

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        full = result.pop("_full_evidence", None)
        if not params.get("target") or full is None:
            return None
        return evidence_target_from_url(params.get("target", "")) or params.get("target", ""), full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = params.get("target", "")
        if not target or result.get("error"):
            return []

        host, port = host_port_from_url(target)
        if not host:
            return []

        fact: Dict[str, Any] = {"host": host, "port": port}
        if result.get("vulnerable"):
            fact["nosql_vulnerable"] = True
            fact["vulnerability"] = f"Possible NoSQL injection via field '{params.get('field', '')}' -- anomalous response with operator(s): {', '.join(result.get('anomalous_operators', []))}"
            fact["severity"] = "high"
        else:
            fact["nosql_tested"] = True

        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]
        return [fact]
