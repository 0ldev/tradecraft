from __future__ import annotations

import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from tradecraft.adapters.host_header_injection_probe import execute as hhi_execute
from tradecraft.adapters.host_header_injection_probe import parse as hhi_parse
from tradecraft.tools.base import Tool


class HostHeaderInjectionProbe(Tool):
    tool_id = "host_header_injection_probe"

    def run(
        self,
        target: str,
        method: str = "GET",
        body: Optional[str] = None,
        headers_to_test: Optional[str] = None,
        timeout: int = 10,
    ) -> Dict[str, Any]:
        raw = hhi_execute.execute(
            target=target, method=method, body=body,
            headers_to_test=headers_to_test, timeout=timeout,
        )
        if raw.error:
            return {"target": target, "error": raw.error}

        result = hhi_parse.parse(raw)
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
        headers_list = ", ".join(result.get("reflected_headers", []))
        fact: Dict[str, Any] = {
            "host": host,
            "port": port,
            "vulnerability": f"Host header injection: {headers_list} reflected into absolute-URL context (password-reset-link poisoning risk)",
            "severity": "high",
        }
        if evidence_id:
            fact["evidence"] = evidence_id
        return [fact]
