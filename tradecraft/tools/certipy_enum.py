"""
Read-only AD CS enumeration via `certipy find`. Classified as
destructive: false. Belongs to profile 'ad-network'.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.certipy_enum import execute as ce_execute
from tradecraft.adapters.certipy_enum import parse as ce_parse
from tradecraft.tools.base import Tool

# Certipy defaults to LDAPS; plain LDAP is the opt-in fallback.
_LDAP_PORTS = {"ldaps": 636, "ldap": 389}


class CertipyEnum(Tool):
    tool_id = "certipy_enum"

    def is_available(self) -> bool:
        return ce_execute.find_certipy_binary() is not None

    def run(
        self,
        target: str,
        domain: str,
        username: str,
        password: str = "",
        hashes: str = "",
        dc_ip: str = "",
        scheme: str = "ldaps",
        enabled_only: bool = False,
        vulnerable_only: bool = False,
        hide_admins: bool = False,
        dc_only: bool = False,
    ) -> Dict[str, Any]:
        raw = ce_execute.execute(
            target=target,
            domain=domain,
            username=username,
            password=password,
            hashes=hashes,
            dc_ip=dc_ip,
            scheme=scheme,
            enabled_only=enabled_only,
            vulnerable_only=vulnerable_only,
            hide_admins=hide_admins,
            dc_only=dc_only,
        )
        parsed = ce_parse.parse_certipy_enum_result(raw)

        if raw.json_output or raw.stdout or raw.stderr:
            # Evidence is the full Certipy JSON (capped) plus the raw
            # transcript, so a later review can see every property rather
            # than only the capped model-facing view.
            parsed["_full_evidence"] = {
                "target": raw.target,
                "domain": raw.domain,
                "scheme": raw.scheme,
                "json": ce_parse.cap_evidence(raw.json_output or ""),
                "raw_stdout": ce_parse.cap_evidence(raw.stdout),
                "raw_stderr": ce_parse.cap_evidence(raw.stderr),
            }

        return parsed

    def extract_evidence(
        self, params: Dict[str, Any], result: Dict[str, Any]
    ) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        host = ce_parse.normalize_target_host(target)
        return (host or target), full

    def extract_facts(
        self, params: Dict[str, Any], result: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        if result.get("status") != "success":
            return []

        target = params.get("target", "")
        host = ce_parse.normalize_target_host(target)
        if not host:
            return []

        scheme = result.get("scheme") or "ldaps"
        fact: Dict[str, Any] = {
            "host": host,
            "port": _LDAP_PORTS.get(scheme, _LDAP_PORTS["ldaps"]),
            "protocol": scheme,
            "adcs_enumerated": True,
            "adcs_ca_count": result.get("ca_count", 0),
            "adcs_template_count": result.get("template_count", 0),
            "adcs_vulnerable_ca_count": result.get("vulnerable_ca_count", 0),
            "adcs_vulnerable_template_count": result.get(
                "vulnerable_template_count", 0
            ),
        }
        if result.get("domain"):
            fact["ad_domain"] = result["domain"]
        if (
            result.get("vulnerable_ca_count")
            or result.get("vulnerable_template_count")
        ):
            fact["adcs_vulnerable"] = True
        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]
        return [fact]
