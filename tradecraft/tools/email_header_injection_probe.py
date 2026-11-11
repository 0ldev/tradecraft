"""
destructive: true -- every call performs 2 real
writes/side effects against live state (see
config/tools/email_header_injection_probe.yaml).
"""
from __future__ import annotations

import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from tradecraft.adapters.email_header_injection_probe import execute as ehi_execute
from tradecraft.adapters.email_header_injection_probe import parse as ehi_parse
from tradecraft.tools.base import Tool


class EmailHeaderInjectionProbe(Tool):
    tool_id = "email_header_injection_probe"

    def run(
        self,
        target: str,
        body: str,
        field_to_inject: str,
        method: str = "POST",
        bcc_marker: Optional[str] = None,
        headers: Optional[str] = None,
        timeout: int = 10,
    ) -> Dict[str, Any]:
        raw = ehi_execute.execute(
            target=target, body=body, field_to_inject=field_to_inject,
            method=method, bcc_marker=bcc_marker, headers=headers, timeout=timeout,
        )
        if raw.error:
            return {"target": target, "error": raw.error}

        result = ehi_parse.parse(raw)
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
        variants = ", ".join(result.get("accepted_variants", []))
        fact: Dict[str, Any] = {
            "host": host,
            "port": port,
            "vulnerability": f"Email header injection: CRLF Bcc injection accepted via {variants} "
                              "(delivery unconfirmed)",
            "severity": "medium",
        }
        if evidence_id:
            fact["evidence"] = evidence_id
        return [fact]
