from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.kiterunner.execute import execute as run_kiterunner
from tradecraft.adapters.kiterunner.parse import (
    host_port_from_target,
    parse_kiterunner_output,
)
from tradecraft.tools.base import Tool


class Kiterunner(Tool):
    tool_id = "kiterunner"

    def run(
        self,
        target: str,
        wordlist: str = "api-routes.kite",
    ) -> Dict[str, Any]:
        raw = run_kiterunner(target=target, wordlist=wordlist)
        if raw.error:
            return {
                "target": target,
                "total_endpoints": 0,
                "endpoints": [],
                "error": raw.error,
            }

        parsed = parse_kiterunner_output(raw.stdout, target_url=raw.target_url)
        endpoints = parsed.get("endpoints", [])

        res: Dict[str, Any] = {
            "target": target,
            "total_endpoints": len(endpoints),
        }

        if len(endpoints) > 15:
            res["endpoints"] = endpoints[:15]
            res["omitted_endpoints"] = len(endpoints) - 15
            res["note"] = (
                f"{len(endpoints) - 15} more endpoints omitted to conserve context. "
                "Use search_evidence to inspect details."
            )
        else:
            res["endpoints"] = endpoints

        res["_full_evidence"] = {
            "target": target,
            "total_endpoints": len(endpoints),
            "endpoints": endpoints,
            "raw_stdout": raw.stdout,
        }
        return res

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        host, _ = host_port_from_target(target)
        canonical = host if host else target
        return canonical, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = params.get("target", "")
        if not target:
            return []
        host, port = host_port_from_target(target)
        total_endpoints = result.get("total_endpoints", 0)

        fact: Dict[str, Any] = {"host": host, "port": port}
        if total_endpoints > 0:
            fact["api_endpoints_count"] = total_endpoints
        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]

        if len(fact) > 2:
            return [fact]
        return []
