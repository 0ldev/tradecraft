from __future__ import annotations

import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from tradecraft.adapters.prototype_pollution_probe import execute as ppp_execute
from tradecraft.adapters.prototype_pollution_probe import parse as ppp_parse
from tradecraft.tools.base import Tool


class PrototypePollutionProbe(Tool):
    tool_id = "prototype_pollution_probe"

    def run(
        self,
        target: str,
        verify_url: Optional[str] = None,
        body: Optional[str] = None,
        timeout: int = 10,
    ) -> Dict[str, Any]:
        raw = ppp_execute.execute(target=target, verify_url=verify_url, body=body, timeout=timeout)
        if raw.error:
            return {"target": target, "error": raw.error}

        result = ppp_parse.parse(raw)
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
        if "error" in result or not result.get("vulnerable"):
            return []
        parsed = urllib.parse.urlsplit(result.get("target", "") or params.get("target", ""))
        host = parsed.hostname or params.get("target", "")
        if not host:
            return []
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        evidence_id = result.get("evidence_id")
        severity = "high" if result.get("leaked_cross_endpoint") else "medium"
        fact: Dict[str, Any] = {
            "host": host,
            "port": port,
            "vulnerability": "Prototype pollution: injected __proto__/constructor.prototype property reflected"
            + (" across a separate endpoint (confirmed global pollution)" if result.get("leaked_cross_endpoint") else ""),
            "severity": severity,
        }
        if evidence_id:
            fact["evidence"] = evidence_id
        return [fact]
