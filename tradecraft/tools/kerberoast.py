"""
destructive: true -- see config/tools/kerberoast.yaml and docs/policy.md.
This file implements no gating itself; the contract's declaration is
what the existing --allow-destructive mechanism reads.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.kerberoast import execute as kerberoast_execute
from tradecraft.adapters.kerberoast import parse as kerberoast_parse
from tradecraft.tools.base import Tool


class Kerberoast(Tool):
    tool_id = "kerberoast"

    def run(
        self,
        target: str,
        domain: str,
        username: str,
        password: str = "",
        hashes: str = "",
        dc_ip: str = "",
    ) -> Dict[str, Any]:
        raw = kerberoast_execute.execute(
            target=target,
            domain=domain,
            username=username,
            password=password,
            hashes=hashes,
            dc_ip=dc_ip,
        )
        return kerberoast_parse.parse_kerberoast_result(raw)

    def extract_evidence(
        self, params: Dict[str, Any], result: Dict[str, Any]
    ) -> Tuple[str, Any] | None:
        host = kerberoast_parse.normalize_target_host(params.get("target", ""))
        full = result.pop("_full_evidence", None)
        if not host or full is None:
            return None
        return host, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        if "error" in result:
            return []
        # Same host key certipy_enum/bloodhound use for this DC, so a
        # separately-reported host:port form of the same target still
        # merges onto the same FactStore record instead of fragmenting it.
        host = kerberoast_parse.normalize_target_host(params.get("target", ""))
        if not host:
            return []
        total = result.get("total_hashes", 0)
        if not total:
            return []
        fact: Dict[str, Any] = {
            "host": host,
            "port": 88,  # Kerberos
            "kerberoastable_accounts": total,
        }
        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]
        return [fact]
