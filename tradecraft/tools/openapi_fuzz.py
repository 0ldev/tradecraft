from __future__ import annotations

import urllib.parse
from typing import Any, Dict, List, Tuple

from tradecraft.adapters.openapi_fuzz import execute as fuzz_execute
from tradecraft.adapters.openapi_fuzz import parse as fuzz_parse
from tradecraft.tools.base import Tool


class OpenApiFuzz(Tool):
    tool_id = "openapi_fuzz"

    def run(
        self,
        target: str,
        spec_url: str = "",
        spec_content: str = "",
        auth_header: str = "",
    ) -> Dict[str, Any]:
        raw = fuzz_execute.execute(
            target=target,
            spec_url=spec_url,
            spec_content=spec_content,
            auth_header=auth_header,
        )
        parsed = fuzz_parse.parse_openapi_fuzz_result(raw)
        if raw.endpoints_tested:
            parsed["_full_evidence"] = {
                "target": target,
                "endpoints_tested": len(raw.endpoints_tested),
                "anomalies": parsed.get("anomalies", []),
            }
        return parsed

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target") or result.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        parsed = urllib.parse.urlsplit(target if "://" in target else f"https://{target}")
        host = parsed.hostname or target
        return host, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = params.get("target") or result.get("target", "")
        if not target or not result.get("anomalies_found"):
            return []
        parsed = urllib.parse.urlsplit(target if "://" in target else f"https://{target}")
        host = parsed.hostname or target
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return [
            {
                "host": host,
                "port": port,
                "api_anomalies_found": True,
                "api_anomalies_count": result.get("anomalies_found", 0),
            }
        ]
