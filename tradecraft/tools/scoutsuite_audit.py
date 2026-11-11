"""
Read-only multi-cloud misconfiguration
audit via ScoutSuite (`scout`), using a cloud credential already obtained
some other way (trufflehog, a metadata-endpoint probe, etc). Classified as
destructive: false -- ScoutSuite only describes and lists provider
configuration. Belongs to profiles 'cloud' and 'web'.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.cloudenum.parse import host_port_from_target
from tradecraft.adapters.scoutsuite_audit import execute as scout_execute
from tradecraft.adapters.scoutsuite_audit import parse as scout_parse
from tradecraft.tools.base import Tool


class ScoutsuiteAudit(Tool):
    tool_id = "scoutsuite_audit"

    def is_available(self) -> bool:
        return scout_execute.is_available()

    def run(
        self,
        target: str,
        provider: str,
        credential: str,
        services: str = "",
    ) -> Dict[str, Any]:
        raw = scout_execute.execute(
            target=target,
            provider=provider,
            credential=credential,
            services=services or None,
        )
        result = scout_parse.parse_scoutsuite_result(raw)
        report = result.pop("_report", None)
        if report is not None:
            result["_full_evidence"] = scout_parse.build_full_evidence(
                target, raw.provider, report
            )
        return result

    def extract_evidence(
        self, params: Dict[str, Any], result: Dict[str, Any]
    ) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        return target, full

    def extract_facts(
        self, params: Dict[str, Any], result: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        target = params.get("target", "")
        if not target or result.get("status") != "success":
            return []

        host, port = host_port_from_target(target)
        fact: Dict[str, Any] = {"host": host, "port": port}
        fact["cloud_audit_scoutsuite_tested"] = True
        flagged = result.get("total_findings", 0)
        if flagged:
            fact["cloud_audit_scoutsuite_flagged"] = flagged
        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]
        return [fact]
