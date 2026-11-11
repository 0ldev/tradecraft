"""
alg=none forged-token probe across
common identity endpoints. Classified as destructive: true.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

from tradecraft.adapters.identity_auth_bypass import execute as iab_execute
from tradecraft.adapters.identity_auth_bypass import parse as iab_parse
from tradecraft.tools.base import Tool


class IdentityAuthBypass(Tool):
    tool_id = "identity_auth_bypass"

    def run(self, target: str, token: str, test_path: str = "") -> Dict[str, Any]:
        raw = iab_execute.execute(target=target, token=token, test_path=test_path)
        parsed = iab_parse.parse_result(raw)
        if parsed.get("vulnerable"):
            parsed["_full_evidence"] = {
                "target": parsed.get("target"),
                "identity_url": parsed.get("identity_url"),
                "baseline_status": parsed.get("baseline_status"),
                "forged_status": parsed.get("forged_status"),
                "forged_token": parsed.get("forged_token"),
            }
        return parsed

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        parsed = urlparse(iab_parse.normalize_base_url(target))
        return parsed.netloc or target, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = params.get("target", "")
        if not target or not result.get("vulnerable"):
            return []
        parsed = urlparse(iab_parse.normalize_base_url(target))
        host = parsed.hostname or target
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        fact: Dict[str, Any] = {
            "host": host,
            "port": port,
            "identity_alg_none_bypass": True,
        }
        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]
        return [fact]
