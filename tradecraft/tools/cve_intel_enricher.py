from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

import tradecraft.adapters.cve_intel_enricher.execute as enricher_execute
import tradecraft.adapters.cve_intel_enricher.parse as enricher_parse
from tradecraft.tools.base import Tool


class CveIntelEnricher(Tool):
    tool_id = "cve_intel_enricher"

    def run(
        self,
        cve: str,
        min_epss: Optional[float] = None,
        timeout: int = enricher_execute.DEFAULT_TIMEOUT,
    ) -> Dict[str, Any]:
        raw = enricher_execute.execute(
            cve=cve,
            min_epss=min_epss,
            timeout=timeout,
        )
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

        parsed = enricher_parse.parse_cve_intel(raw)
        res: Dict[str, Any] = {
            "cves_requested": parsed["cves_requested"],
            "total_evaluated": parsed["total_evaluated"],
            "critical_count": parsed["critical_count"],
            "high_count": parsed["high_count"],
            "kev_count": parsed["kev_count"],
            "ai_stack_count": parsed["ai_stack_count"],
            "sources": parsed["sources"],
            "entries": parsed["entries"],
        }

        if parsed["entries"]:
            res["_full_evidence"] = {
                "cves_requested": parsed["cves_requested"],
                "sources": parsed["sources"],
                "entries": parsed["entries"],
            }

        return res

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        cve = params.get("cve", "")
        full = result.pop("_full_evidence", None)
        if not cve or full is None:
            return None
        return cve, full
