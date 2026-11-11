"""
Read-only information disclosure.
"""
from __future__ import annotations

import urllib.parse
from typing import Any, Dict, List, Tuple

from tradecraft.adapters.ntlm_info_disclosure_probe import execute as ntlm_execute
from tradecraft.adapters.ntlm_info_disclosure_probe import parse as ntlm_parse
from tradecraft.tools.base import Tool


class NtlmInfoDisclosureProbe(Tool):
    tool_id = "ntlm_info_disclosure_probe"

    def run(self, target: str, timeout: int = 10) -> Dict[str, Any]:
        raw = ntlm_execute.execute(target=target, timeout=timeout)
        result = ntlm_parse.parse(raw)
        if result.get("disclosed"):
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
        if not result.get("disclosed"):
            return []
        target = result.get("target", "") or params.get("target", "")
        parsed = urllib.parse.urlsplit(target if "://" in target else f"https://{target}")
        host = parsed.hostname or target
        if not host:
            return []
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        domain = result.get("domain") or ""
        computer = result.get("computer_name") or ""
        detail = ", ".join(part for part in (domain, computer) if part)
        fact: Dict[str, Any] = {
            "host": host,
            "port": port,
            "vulnerability": f"NTLM information disclosure: internal AD identity {detail}",
            "severity": "medium",
        }
        evidence_id = result.get("evidence_id")
        if evidence_id:
            fact["evidence"] = evidence_id
        return [fact]
