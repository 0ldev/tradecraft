from __future__ import annotations

import urllib.parse
from typing import Any, Dict, List, Tuple

from tradecraft.adapters.sensitive_file_probe import execute as sfp_execute
from tradecraft.adapters.sensitive_file_probe import parse as sfp_parse
from tradecraft.tools.base import Tool


class SensitiveFileProbe(Tool):
    tool_id = "sensitive_file_probe"

    def run(self, target: str, timeout: int = 10) -> Dict[str, Any]:
        raw = sfp_execute.execute(target=target, timeout=timeout)
        if raw.error:
            return {"target": target, "error": raw.error}

        result = sfp_parse.parse(raw)
        result["_full_evidence"] = dict(result)
        return result

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        parsed = urllib.parse.urlsplit(target if "://" in target else f"https://{target}")
        host = parsed.hostname or target
        return host, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        if "error" in result or not result.get("hits_found"):
            return []
        parsed = urllib.parse.urlsplit(result.get("target", "") or params.get("target", ""))
        host = parsed.hostname or params.get("target", "")
        if not host:
            return []
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        evidence_id = result.get("evidence_id")
        paths = ", ".join(h["path"] for h in result.get("hits", []))
        fact: Dict[str, Any] = {
            "host": host,
            "port": port,
            "vulnerability": f"Sensitive file(s) publicly exposed: {paths}",
            "severity": "high",
        }
        if evidence_id:
            fact["evidence"] = evidence_id
        return [fact]
