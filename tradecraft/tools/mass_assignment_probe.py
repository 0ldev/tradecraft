"""
destructive: true -- every call performs real writes
against live state (see config/tools/mass_assignment_probe.yaml).
"""
from __future__ import annotations

import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from tradecraft.adapters.mass_assignment_probe import execute as map_execute
from tradecraft.adapters.mass_assignment_probe import parse as map_parse
from tradecraft.tools.base import Tool


class MassAssignmentProbe(Tool):
    tool_id = "mass_assignment_probe"

    def run(
        self,
        target: str,
        body: str,
        method: str = "POST",
        candidate_fields: Optional[str] = None,
        headers: Optional[str] = None,
        timeout: int = 10,
    ) -> Dict[str, Any]:
        raw = map_execute.execute(
            target=target, body=body, method=method,
            candidate_fields=candidate_fields, headers=headers, timeout=timeout,
        )
        if raw.error:
            return {"target": target, "error": raw.error}

        result = map_parse.parse(raw)
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
        if "error" in result or not result.get("confirmed_accepted"):
            return []
        parsed = urllib.parse.urlsplit(result.get("target", "") or params.get("target", ""))
        host = parsed.hostname or params.get("target", "")
        if not host:
            return []
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        evidence_id = result.get("evidence_id")
        confirmed_fields = ", ".join(
            a["field"] for a in result.get("attempts", []) if a.get("classification") == "accepted_confirmed"
        )
        fact: Dict[str, Any] = {
            "host": host,
            "port": port,
            "vulnerability": f"Mass assignment: privilege-escalating field(s) accepted: {confirmed_fields}",
            "severity": "high",
        }
        if evidence_id:
            fact["evidence"] = evidence_id
        return [fact]
