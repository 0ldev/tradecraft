"""
Non-destructive: discovery GET plus bounded GetCredentialType POSTs,
no sign-in. Belongs to profile 'cloud'.
"""
from __future__ import annotations

from typing import Any, Dict, List

from tradecraft.adapters.azure_tenant_recon import execute as att_execute
from tradecraft.adapters.azure_tenant_recon import parse as att_parse
from tradecraft.tools.base import Tool


class AzureTenantRecon(Tool):
    tool_id = "azure_tenant_recon"

    def run(self, domain: str, usernames: str = "", timeout: int = 10) -> Dict[str, Any]:
        raw = att_execute.execute(domain=domain, usernames=usernames, timeout=timeout)
        return att_parse.parse_azure_tenant_result(raw)

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        domain = params.get("domain", "") or result.get("domain", "")
        if not domain or not result.get("is_azure_ad"):
            return []
        fact: Dict[str, Any] = {
            "host": domain,
            "port": 443,
            "azure_ad_tenant": result.get("tenant_id"),
        }
        usernames = result.get("existing_usernames") or []
        if usernames:
            fact["azure_ad_users"] = ", ".join(usernames[:10])
        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]
        return [fact]
