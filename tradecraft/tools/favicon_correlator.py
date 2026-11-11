from __future__ import annotations

import os
import urllib.parse
from typing import Any, Dict, List

from tradecraft.adapters.favicon_correlator import execute as favicon_execute
from tradecraft.adapters.favicon_correlator import parse as favicon_parse
from tradecraft.tools.base import Tool


class FaviconCorrelator(Tool):
    tool_id = "favicon_correlator"

    def is_available(self) -> bool:
        return bool(os.environ.get("SHODAN_API_KEY"))

    def run(self, target: str) -> Dict[str, Any]:
        api_key = os.environ.get("SHODAN_API_KEY", "").strip()
        if not api_key:
            return {
                "target": target,
                "favicon_hash": None,
                "correlated_ips": [],
                "error": "SHODAN_API_KEY not configured in environment",
            }

        raw = favicon_execute.execute(target, api_key)
        if raw.error and raw.shodan_json is None:
            return {
                "target": target,
                "favicon_hash": raw.favicon_hash,
                "correlated_ips": [],
                "error": raw.error,
            }

        correlated_ips = favicon_parse.parse_shodan_matches(raw.shodan_json or {})
        result: Dict[str, Any] = {
            "target": target,
            "favicon_hash": raw.favicon_hash,
            "correlated_ips": correlated_ips,
        }
        if raw.error:
            result["error"] = raw.error
        return result

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = params.get("target", "")
        correlated = result.get("correlated_ips", [])
        if not target or not correlated:
            return []
        parsed = urllib.parse.urlsplit(target if "://" in target else f"//{target}")
        host = parsed.hostname or target
        if not host:
            return []
        return [{"host": host, "favicon_correlated_ips": correlated}]
