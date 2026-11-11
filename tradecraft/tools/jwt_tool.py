from __future__ import annotations

import urllib.parse
from typing import Any, Dict, List, Tuple

from tradecraft.adapters.jwt_tool import execute as jt_execute
from tradecraft.adapters.jwt_tool import parse as jt_parse
from tradecraft.tools.base import Tool


class JwtTool(Tool):
    tool_id = "jwt_tool"

    def is_available(self) -> bool:
        return jt_execute.find_script() is not None

    def run(
        self,
        token: str,
        target_url: str = "",
        header_name: str = "Authorization",
        header_prefix: str = "Bearer ",
        canary_claim: str = "",
    ) -> Dict[str, Any]:
        raw = jt_execute.execute(
            token=token,
            target_url=target_url,
            header_name=header_name,
            header_prefix=header_prefix,
            canary_claim=canary_claim,
        )
        parsed = jt_parse.parse_jwt_tool_output(raw)
        if raw.stdout or raw.stderr:
            parsed["_full_evidence"] = {
                "token": token,
                "target_url": target_url,
                "raw_stdout": raw.stdout,
                "raw_stderr": raw.stderr,
                "forged_tokens": parsed.get("forged_tokens", []),
            }
        return parsed

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target_url = params.get("target_url") or result.get("target_url", "")
        full = result.pop("_full_evidence", None)
        if not target_url or full is None:
            return None
        parsed = urllib.parse.urlsplit(target_url if "://" in target_url else f"https://{target_url}")
        host = parsed.hostname or target_url
        return host, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        target_url = params.get("target_url") or result.get("target_url", "")
        if not target_url or not result.get("vulnerable"):
            return []
        parsed = urllib.parse.urlsplit(target_url if "://" in target_url else f"https://{target_url}")
        host = parsed.hostname or target_url
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return [
            {
                "host": host,
                "port": port,
                "jwt_vulnerable": True,
                "jwt_tamper_findings": result.get("total_findings", 0),
            }
        ]
