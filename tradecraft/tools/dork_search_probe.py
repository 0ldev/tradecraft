from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from tradecraft.adapters.dork_search_probe import execute as dork_execute
from tradecraft.adapters.dork_search_probe import parse as dork_parse
from tradecraft.tools.base import Tool


def _extract_site_domain(query: str) -> Optional[str]:
    match = re.search(r"site:([\w.-]+)", query)
    return match.group(1) if match else None


class DorkSearchProbe(Tool):
    tool_id = "dork_search_probe"

    def run(self, query: str, num_results: int = 10, timeout: int = 10) -> Dict[str, Any]:
        raw = dork_execute.execute(query=query, num_results=num_results, timeout=timeout)
        result = dork_parse.parse(raw)
        if result.get("error"):
            return result

        # Results are already capped at 10 by the adapter, so the full set is
        # small enough to hand over as-is.
        result["_full_evidence"] = {
            "query": result["query"],
            "results": result["results"],
        }
        return result

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        query = params.get("query", "")
        full = result.pop("_full_evidence", None)
        if full is None:
            return None
        target_key = _extract_site_domain(query) or query
        return target_key, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not result.get("result_count"):
            return []
        query = params.get("query", "")
        host = _extract_site_domain(query)
        if host is None:
            return []
        fact: Dict[str, Any] = {"host": host, "port": 0, "dork_results_found": result.get("result_count")}
        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]
        return [fact]
