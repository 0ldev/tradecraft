"""
Destructive: true -- every request in the burst is a real request, and a
limited server-side resource (a single-use coupon, a rate-limit counter)
may be genuinely consumed. Hard-capped at 20 requests per call in the
adapter, independent of --allow-destructive.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from tradecraft.adapters.http_request.parse import evidence_target_from_url, host_port_from_url
from tradecraft.adapters.race_condition_probe.execute import DEFAULT_REQUESTS
from tradecraft.adapters.race_condition_probe.execute import execute as run_race_condition_probe
from tradecraft.adapters.race_condition_probe.parse import parse as parse_race_condition
from tradecraft.tools.base import Tool


class RaceConditionProbe(Tool):
    tool_id = "race_condition_probe"

    def run(
        self,
        url: str,
        method: str = "POST",
        headers: Optional[str] = None,
        data: Optional[str] = None,
        request_count: int = DEFAULT_REQUESTS,
        success_marker: Optional[str] = None,
        timeout: int = 10,
    ) -> Dict[str, Any]:
        raw = run_race_condition_probe(
            url=url,
            method=method,
            headers=headers,
            data=data,
            request_count=request_count,
            success_marker=success_marker,
            timeout=timeout,
        )

        parsed = parse_race_condition(raw)

        # Full, untruncated per-attempt detail (including body snippets) for
        # the EvidenceStore; the model-facing dict above stays small.
        parsed["_full_evidence"] = {
            "url": raw.url,
            "method": raw.method,
            "requested_count": raw.requested_count,
            "success_count": raw.success_count,
            "likely_race_condition": raw.likely_race_condition,
            "error": raw.error,
            "attempts": [
                {
                    "index": a.index,
                    "status_code": a.status_code,
                    "success_marker_found": a.success_marker_found,
                    "duration_seconds": a.duration_seconds,
                    "error": a.error,
                    "body_snippet": a.body_snippet,
                }
                for a in raw.attempts
            ],
        }

        return parsed

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        url = params.get("url", "")
        full = result.pop("_full_evidence", None)
        if not url or full is None:
            return None
        return (evidence_target_from_url(url) or url), full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not result.get("url"):
            return []
        host, port = host_port_from_url(result["url"])

        fact: Dict[str, Any] = {"host": host, "port": port}
        if result.get("likely_race_condition"):
            fact["vulnerability"] = "Likely race condition (TOCTOU) -- multiple concurrent requests succeeded against what should be a single-use/limited resource"
            fact["severity"] = "high"
            fact["race_success_count"] = result.get("success_count")
        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]

        if len(fact) > 2:
            return [fact]
        return []
