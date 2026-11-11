"""
Active Directory attack path graph collection.
Classified as destructive: false. Belongs to profile 'ad-network'.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.bloodhound import execute as bh_execute
from tradecraft.adapters.bloodhound import parse as bh_parse
from tradecraft.tools.base import Tool


class Bloodhound(Tool):
    tool_id = "bloodhound"

    def run(
        self,
        target: str,
        domain: str,
        username: str = "",
        password: str = "",
        hashes: str = "",
        collection_method: str = "DCOnly",
        nameserver: str = "",
        use_ldaps: bool = False,
        kerberos: bool = False,
        ccache_b64: str = "",
    ) -> Dict[str, Any]:
        raw = bh_execute.execute(
            target=target,
            domain=domain,
            username=username,
            password=password,
            hashes=hashes,
            collection_method=collection_method,
            nameserver=nameserver,
            use_ldaps=use_ldaps,
            kerberos=kerberos,
            ccache_b64=ccache_b64,
        )
        parsed = bh_parse.parse_bloodhound_result(raw)

        if parsed.get("total_objects_collected", 0) > 0 or raw.json_files:
            parsed["_full_evidence"] = {
                "target": raw.target,
                "domain": raw.domain,
                "collection_method": raw.collection_method,
                "total_objects_collected": parsed.get("total_objects_collected", 0),
                "counts": parsed.get("counts", {}),
                "files_generated": parsed.get("files_generated", []),
                "json_files": raw.json_files,
                "raw_stdout": raw.stdout,
                "raw_stderr": raw.stderr,
            }

        return parsed

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        host = bh_parse.normalize_target_host(target)
        return host, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = params.get("target", "")
        total = result.get("total_objects_collected", 0)
        if not target or total == 0:
            return []

        port = 636 if params.get("use_ldaps", False) else 389
        host, parsed_port = bh_parse.parse_host_port(target, default_port=port)
        fact: Dict[str, Any] = {
            "host": host,
            "port": parsed_port,
            "ad_domain": result.get("domain", ""),
            "bloodhound_collection_method": result.get("collection_method", "DCOnly"),
            "ad_bloodhound_objects_count": total,
        }

        counts = result.get("counts", {})
        if "users" in counts:
            fact["ad_users_count"] = counts["users"]
        if "groups" in counts:
            fact["ad_groups_count"] = counts["groups"]
        if "computers" in counts:
            fact["ad_computers_count"] = counts["computers"]
        if "domains" in counts:
            fact["ad_domains_count"] = counts["domains"]

        insights = result.get("insights", {})
        if "admin_users" in insights and insights["admin_users"]:
            fact["ad_admin_users_count"] = len(insights["admin_users"])
        if "kerberoastable_users" in insights and insights["kerberoastable_users"]:
            fact["ad_kerberoastable_users_count"] = len(insights["kerberoastable_users"])

        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]

        return [fact]
