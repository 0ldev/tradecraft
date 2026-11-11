"""
Cache Poison Probe tool: tests whether a URL's web cache can be poisoned via unkeyed headers.
Glues config/tools/cache_poison_probe.yaml to tradecraft.adapters.cache_poison_probe.
"""
from __future__ import annotations

from urllib.parse import urlparse
from typing import Any, Dict, List, Tuple

from tradecraft.adapters.cache_poison_probe import execute as cp_execute
from tradecraft.adapters.cache_poison_probe import parse as cp_parse
from tradecraft.tools.base import Tool


class CachePoisonProbe(Tool):
    tool_id = "cache_poison_probe"

    def run(self, target: str) -> Dict[str, Any]:
        attempts = cp_execute.execute(target)
        parsed = cp_parse.parse_all(attempts)
        res = {"target": target, **parsed}
        res["_full_evidence"] = {
            "target": target,
            "vulnerable": parsed["vulnerable"],
            "vulnerable_headers": parsed["vulnerable_headers"],
            "attempts": [
                {
                    "header_name": a.header_name,
                    "marker_value": a.marker_value,
                    "poison_status": a.poison_status,
                    "clean_status": a.clean_status,
                    "attempted_clean": a.attempted_clean,
                    "error": a.error,
                    "poison_body": a.poison_body,
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
        parsed = urlparse(target)
        canonical_target = parsed.netloc or target
        return canonical_target, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not result.get("vulnerable"):
            return []
        target = params.get("target", "")
        parsed = urlparse(target)
        host = parsed.hostname or target
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        vulnerable_headers = result.get("vulnerable_headers", [])
        fact: Dict[str, Any] = {
            "host": host,
            "port": port,
            "cache_poisoning": f"vulnerable via {', '.join(vulnerable_headers)}",
        }
        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]
        return [fact]
