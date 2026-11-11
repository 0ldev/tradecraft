"""
Cache Deception Probe tool: tests whether an authenticated page can be cached under a
static-looking URL and then served to unauthenticated requesters.
Glues config/tools/cache_deception_probe.yaml to tradecraft.adapters.cache_deception_probe.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.cache_deception_probe import execute as cd_execute
from tradecraft.adapters.cache_deception_probe import parse as cd_parse
from tradecraft.adapters.http_request.parse import evidence_target_from_url, host_port_from_url
from tradecraft.tools.base import Tool


class CacheDeceptionProbe(Tool):
    tool_id = "cache_deception_probe"

    def run(self, target: str, success_marker: str, auth_headers: str, timeout: int = 10) -> Dict[str, Any]:
        attempts = cd_execute.execute(
            target=target,
            success_marker=success_marker,
            auth_headers=auth_headers,
            timeout=timeout,
        )
        parsed = cd_parse.parse(attempts)
        res = {"target": target, **parsed}
        res["_full_evidence"] = {
            "target": target,
            "attempts": [
                {
                    "suffix": a.suffix,
                    "crafted_url": a.crafted_url,
                    "authed_status": a.authed_status,
                    "authed_marker_found": a.authed_marker_found,
                    "clean_status": a.clean_status,
                    "clean_marker_found": a.clean_marker_found,
                    "deception_confirmed": a.deception_confirmed,
                    "error": a.error,
                    "authed_body": a.authed_body,
                    "clean_body": a.clean_body,
                }
                for a in attempts
            ],
        }
        return res

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
            "vulnerability": f"Web cache deception confirmed: authenticated content leaked to unauthenticated requests via suffix(es) {', '.join(result.get('confirmed_suffixes', []))}",
            "severity": "high",
        }
        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]
        return [fact]
