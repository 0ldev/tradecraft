"""
Active Directory domain and object enumeration.
Classified as destructive: false. Belongs to profile 'ad-network'.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.powerview import execute as pv_execute
from tradecraft.adapters.powerview import parse as pv_parse
from tradecraft.tools.base import Tool


class PowerView(Tool):
    tool_id = "powerview"

    def run(
        self,
        target: str,
        domain: str,
        username: str = "",
        password: str = "",
        hashes: str = "",
        query: str = "Get-DomainUser",
        use_ldap: bool = False,
        kerberos: bool = False,
        ccache_b64: str = "",
    ) -> Dict[str, Any]:
        raw = pv_execute.execute(
            target=target,
            domain=domain,
            username=username,
            password=password,
            hashes=hashes,
            query=query,
            use_ldap=use_ldap,
            kerberos=kerberos,
            ccache_b64=ccache_b64,
        )
        parsed = pv_parse.parse_powerview_result(raw)

        if parsed.get("total_entries", 0) > 0:
            parsed["_full_evidence"] = {
                "target": raw.target,
                "domain": raw.domain,
                "query": raw.query,
                "total_entries": parsed["total_entries"],
                "entries": parsed.get("_all_entries", parsed.get("entries", [])),
                "raw_stdout": raw.stdout,
            }

        return parsed

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        host = pv_parse.normalize_target_host(target)
        return host, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = params.get("target", "")
        total = result.get("total_entries", 0)
        if not target or total == 0:
            return []

        port = 389 if params.get("use_ldap", False) else 636
        host, parsed_port = pv_parse.parse_host_port(target, default_port=port)
        fact: Dict[str, Any] = {
            "host": host,
            "port": parsed_port,
            "ad_domain": result.get("domain", ""),
            "powerview_query": result.get("query", ""),
            "ad_objects_count": total,
        }

        insights = result.get("insights", {})
        if "users" in insights:
            fact["ad_users_count"] = len(insights["users"])
        if "admin_users" in insights:
            fact["ad_admin_users_count"] = len(insights["admin_users"])
        if "kerberoastable_users" in insights:
            fact["ad_kerberoastable_users_count"] = len(insights["kerberoastable_users"])
        if "computers" in insights:
            fact["ad_computers_count"] = len(insights["computers"])
        if "groups" in insights:
            fact["ad_groups_count"] = len(insights["groups"])
        if "trusts" in insights:
            fact["ad_trusts_count"] = len(insights["trusts"])

        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]

        return [fact]
