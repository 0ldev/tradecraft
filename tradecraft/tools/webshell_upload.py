"""
File-upload webshell planting with
execution confirmation. Classified as destructive: true.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

from tradecraft.adapters.webshell_upload import execute as ws_execute
from tradecraft.adapters.webshell_upload import parse as ws_parse
from tradecraft.tools.base import Tool


class WebshellUpload(Tool):
    tool_id = "webshell_upload"

    def run(self, target: str, cookie: str = "") -> Dict[str, Any]:
        raw = ws_execute.execute(target=target, cookie=cookie)
        parsed = ws_parse.parse_result(raw)
        if parsed.get("planted"):
            parsed["_full_evidence"] = {
                "target": parsed.get("target"),
                "planted_path": parsed.get("planted_path"),
                "planted_url": parsed.get("planted_url"),
                "bypass_used": parsed.get("bypass_used"),
                "execution_output": parsed.get("execution_output"),
                "accepted_uploads": parsed.get("accepted_uploads", []),
            }
        return parsed

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        parsed = urlparse(target if "://" in target else f"http://{target}")
        return parsed.netloc or target, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = params.get("target", "")
        if not target or not result.get("planted"):
            return []
        parsed = urlparse(target if "://" in target else f"http://{target}")
        host = parsed.hostname or target
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        fact: Dict[str, Any] = {
            "host": host,
            "port": port,
            "webshell_planted": result.get("planted_path"),
        }
        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]
        return [fact]
