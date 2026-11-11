from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from tradecraft.adapters.email_auth_posture import execute as email_execute
from tradecraft.adapters.email_auth_posture import parse as email_parse
from tradecraft.tools.base import Tool


class EmailAuthPosture(Tool):
    tool_id = "email_auth_posture"

    def run(
        self,
        target: str,
        dkim_selectors: Optional[str] = None,
    ) -> Dict[str, Any]:
        selectors = (
            [s.strip() for s in dkim_selectors.split(",") if s.strip()]
            if dkim_selectors
            else None
        )
        raw = email_execute.execute(target, dkim_selectors=selectors)
        if raw.error:
            return {"target": target, "error": raw.error}

        parsed = email_parse.parse_result(raw, target)
        parsed["_full_evidence"] = dict(parsed)
        return parsed

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        domain = email_execute.normalize_domain(target)
        canonical = domain if domain else target
        return canonical, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = params.get("target", "")
        if not target:
            return []
        domain = email_execute.normalize_domain(target)
        host = domain if domain else target
        facts: List[Dict[str, Any]] = []
        evidence_id = result.get("evidence_id")

        spf = result.get("spf", {})
        if spf.get("strength") == "missing":
            f = {
                "host": host,
                "port": 25,
                "vulnerability": "No SPF record (email spoofing exposure)",
                "severity": "medium",
            }
            if evidence_id:
                f["evidence"] = evidence_id
            facts.append(f)
        elif spf.get("strength") == "permissive":
            f = {
                "host": host,
                "port": 25,
                "vulnerability": "Permissive SPF policy (+all or no enforcement qualifier)",
                "severity": "medium",
            }
            if evidence_id:
                f["evidence"] = evidence_id
            facts.append(f)

        dmarc = result.get("dmarc", {})
        if dmarc.get("strength") == "missing":
            f = {
                "host": host,
                "port": 25,
                "vulnerability": "No DMARC record (email spoofing/phishing exposure)",
                "severity": "medium",
            }
            if evidence_id:
                f["evidence"] = evidence_id
            facts.append(f)
        elif dmarc.get("strength") == "weak":
            f = {
                "host": host,
                "port": 25,
                "vulnerability": "DMARC policy set to p=none (monitoring only, no enforcement)",
                "severity": "low",
            }
            if evidence_id:
                f["evidence"] = evidence_id
            facts.append(f)

        mta_sts = result.get("mta_sts", {})
        if "mta_sts" in result and mta_sts.get("present") is False:
            f = {
                "host": host,
                "port": 25,
                "vulnerability": "No MTA-STS record (inbound email vulnerable to STARTTLS stripping / downgrade attacks)",
                "severity": "low",
            }
            if evidence_id:
                f["evidence"] = evidence_id
            facts.append(f)
        elif mta_sts.get("mode") == "testing":
            f = {
                "host": host,
                "port": 25,
                "vulnerability": "MTA-STS policy set to testing mode (monitoring only, not enforced)",
                "severity": "low",
            }
            if evidence_id:
                f["evidence"] = evidence_id
            facts.append(f)

        return facts
