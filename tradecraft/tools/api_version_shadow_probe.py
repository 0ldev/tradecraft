"""
Read-only differential-auth probe.
"""
from __future__ import annotations

import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from tradecraft.adapters.api_version_shadow_probe import execute as shadow_execute
from tradecraft.adapters.api_version_shadow_probe import parse as shadow_parse
from tradecraft.tools.base import Tool


class ApiVersionShadowProbe(Tool):
    tool_id = "api_version_shadow_probe"

    def run(
        self,
        target: str,
        method: str = "GET",
        body: Optional[str] = None,
        timeout: int = 10,
    ) -> Dict[str, Any]:
        raw = shadow_execute.execute(target=target, method=method, body=body, timeout=timeout)
        result = shadow_parse.parse(raw)
        if result.get("vulnerable"):
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
        if not result.get("vulnerable"):
            return []
        target = result.get("target", "") or params.get("target", "")
        parsed = urllib.parse.urlsplit(target if "://" in target else f"https://{target}")
        host = parsed.hostname or target
        if not host:
            return []
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        labels = ", ".join(v.get("label", "") for v in result.get("accessible_variants", []))
        fact: Dict[str, Any] = {
            "host": host,
            "port": port,
            "vulnerability": f"Shadow/zombie API version reachable without authentication: {labels}",
            "severity": "high",
        }
        evidence_id = result.get("evidence_id")
        if evidence_id:
            fact["evidence"] = evidence_id
        return [fact]
