"""
SMTP Probe tool: single-shot SMTP capability discovery and VRFY oracle auditing.
Glues config/tools/smtp_probe.yaml to tradecraft.adapters.smtp_probe.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from tradecraft.adapters.smtp_probe.execute import execute as smtp_execute
from tradecraft.adapters.smtp_probe.parse import parse as smtp_parse
from tradecraft.tools.base import Tool


class SmtpProbe(Tool):
    tool_id = "smtp_probe"

    def run(
        self,
        target: str,
        port: int = 25,
        starttls: bool = True,
        vrfy_target: str = "root",
        timeout: int = 5,
    ) -> Dict[str, Any]:
        result = smtp_execute(
            target=target,
            port=port,
            starttls=starttls,
            vrfy_target=vrfy_target,
            timeout=timeout,
        )
        parsed = smtp_parse(result)

        full_evidence = {
            "target": target,
            "host": result.host,
            "port": result.port,
            "connected": result.connected,
            "software": result.software,
            "banner": result.banner,
            "extensions": result.extensions,
            "starttls_advertised": result.starttls_advertised,
            "starttls_active": result.starttls_active,
            "tls_cipher": result.tls_cipher,
            "tls_version": result.tls_version,
            "auth_mechanisms": result.auth_mechanisms,
            "vrfy_tested": result.vrfy_tested,
            "vrfy_target": result.vrfy_target,
            "vrfy_code": result.vrfy_code,
            "vrfy_response": result.vrfy_response,
            "user_enumeration_oracle": result.user_enumeration_oracle,
            "rtt_ms": result.rtt_ms,
            "error": result.error,
            "note": result.note,
        }
        parsed["_full_evidence"] = full_evidence
        return parsed

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        host = result.get("host") or target
        return host, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not result.get("connected"):
            return []
        host = result.get("host") or params.get("target", "")
        port = result.get("port", 25)

        fact: Dict[str, Any] = {
            "host": host,
            "port": port,
            "service": "smtp",
            "state": "open",
        }
        if result.get("software"):
            fact["version"] = result["software"]
        if result.get("banner"):
            fact["banner"] = result["banner"]

        starttls_info = result.get("starttls", {})
        if starttls_info.get("active"):
            fact["starttls"] = True

        facts = [fact]

        vrfy_info = result.get("vrfy", {})
        if vrfy_info.get("user_enumeration_oracle"):
            facts.append({
                "host": host,
                "port": port,
                "service": "smtp",
                "vulnerability": "SMTP VRFY User Enumeration Oracle",
                "severity": "medium",
                "evidence_id": f"smtp_probe:{host}",
            })

        return facts
