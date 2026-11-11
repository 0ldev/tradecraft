from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from tradecraft.adapters.mail_access_probe.execute import execute as mail_execute
from tradecraft.adapters.mail_access_probe.parse import parse_result as mail_parse
from tradecraft.tools.base import Tool


class MailAccessProbe(Tool):
    tool_id = "mail_access_probe"

    def run(
        self,
        target: str,
        port: int = 143,
        protocol: Optional[str] = None,
        timeout: int = 5,
    ) -> Dict[str, Any]:
        raw = mail_execute(
            target=target,
            port=port,
            protocol=protocol,
            timeout=timeout,
        )
        parsed = mail_parse(raw)

        full_evidence = {
            "target": target,
            "host": raw.host,
            "port": raw.port,
            "protocol": raw.protocol,
            "connected": raw.connected,
            "software": parsed.get("software"),
            "banner": raw.banner,
            "is_tls": raw.is_tls,
            "implicit_tls": raw.implicit_tls,
            "starttls_advertised": raw.starttls_advertised,
            "starttls_active": raw.starttls_active,
            "tls_cipher": raw.tls_cipher,
            "tls_version": raw.tls_version,
            "capabilities_pre_tls": raw.capabilities_pre_tls,
            "capabilities_post_tls": raw.capabilities_post_tls,
            "auth_mechanisms": parsed.get("auth_mechanisms", []),
            "security_audit": parsed.get("security_audit", {}),
            "rtt_ms": raw.rtt_ms,
            "error": raw.error,
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
        port = result.get("port", 143)
        proto = result.get("protocol", "imap")

        fact: Dict[str, Any] = {
            "host": host,
            "port": port,
            "service": proto,
            "state": "open",
        }
        if result.get("software"):
            fact["version"] = result["software"]
        if result.get("banner"):
            fact["banner"] = result["banner"]

        tls_info = result.get("tls", {})
        if tls_info.get("active"):
            fact["starttls"] = True

        facts = [fact]

        sec = result.get("security_audit", {})
        if sec.get("cleartext_auth_allowed") and sec.get("vulnerability"):
            facts.append({
                "host": host,
                "port": port,
                "service": proto,
                "vulnerability": sec["vulnerability"],
                "severity": sec.get("severity", "medium"),
                "evidence_id": f"mail_access_probe:{host}",
            })

        return facts
