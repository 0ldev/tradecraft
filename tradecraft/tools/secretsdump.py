"""
destructive: true -- see config/tools/secretsdump.yaml and docs/policy.md.
This file implements no gating itself; the contract's declaration is
what the existing --allow-destructive mechanism reads.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.secretsdump import execute as secretsdump_execute
from tradecraft.adapters.secretsdump import parse as secretsdump_parse
from tradecraft.tools.base import Tool


class Secretsdump(Tool):
    tool_id = "secretsdump"

    def run(
        self,
        target: str,
        domain: str,
        username: str,
        password: str = "",
        hashes: str = "",
        dc_ip: str = "",
        just_dc_user: str = "",
    ) -> Dict[str, Any]:
        raw = secretsdump_execute.execute(
            target=target,
            domain=domain,
            username=username,
            password=password,
            hashes=hashes,
            dc_ip=dc_ip,
            just_dc_user=just_dc_user,
        )
        return secretsdump_parse.parse_secretsdump_result(raw)

    def extract_evidence(
        self, params: Dict[str, Any], result: Dict[str, Any]
    ) -> Tuple[str, Any] | None:
        host = secretsdump_parse.normalize_target_host(params.get("target", ""))
        full = result.pop("_full_evidence", None)
        if not host or full is None:
            return None
        return host, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        if "error" in result:
            return []
        host = secretsdump_parse.normalize_target_host(params.get("target", ""))
        if not host:
            return []
        # total_accounts (distinct usernames), not total_dumped (entry
        # count): one account can yield an NTLM entry plus one entry per
        # Kerberos key type, so total_dumped alone would overstate how
        # many accounts were actually compromised.
        total_accounts = result.get("total_accounts", 0)
        if not total_accounts:
            return []
        fact: Dict[str, Any] = {
            "host": host,
            "port": 445,  # DRSUAPI rides over SMB-named-pipe RPC
            "secretsdump_accounts_dumped": total_accounts,
        }
        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]
        return [fact]
