from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.ffuf import execute as ffuf_execute
from tradecraft.adapters.ffuf import parse as ffuf_parse
from tradecraft.tools.base import Tool


class Ffuf(Tool):
    tool_id = "ffuf"

    def run(
        self,
        target: str,
        wordlist: str = "common",
        extensions: str = "",
        match_codes: str = "all",
        filter_codes: str = "404",
    ) -> Dict[str, Any]:
        raw = ffuf_execute.execute(
            target=target,
            wordlist=wordlist,
            extensions=extensions,
            match_codes=match_codes,
            filter_codes=filter_codes,
        )
        if raw.error:
            return {"target": target, "endpoints": [], "error": raw.error}

        endpoints = ffuf_parse.parse_results(raw.json_output, canary=raw.canary)
        res: Dict[str, Any] = {
            "target": target,
            "total_found": len(endpoints),
            "requests_sent": raw.requests_attempted,
            "duration_seconds": round(raw.duration_seconds, 1),
        }
        if len(endpoints) > 10:
            res["endpoints"] = endpoints[:10]
            res["omitted_endpoints"] = len(endpoints) - 10
            res["note"] = (
                f"{len(endpoints) - 10} more endpoints omitted to conserve context. "
                "Use read_evidence to inspect all."
            )
        else:
            res["endpoints"] = endpoints

        res["_full_evidence"] = {
            "target": target,
            "total_found": len(endpoints),
            "endpoints": endpoints,
        }
        return res

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        host, _ = ffuf_parse.host_port_from_target(target)
        canonical_target = host if host else target
        return canonical_target, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = params.get("target", "")
        if not target:
            return []
        host, port = ffuf_parse.host_port_from_target(target)
        total = result.get("total_found", len(result.get("endpoints", [])))

        fact: Dict[str, Any] = {"host": host, "port": port}
        if total > 0:
            fact["endpoints_discovered"] = total
        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]

        if len(fact) > 2:
            return [fact]
        return []
