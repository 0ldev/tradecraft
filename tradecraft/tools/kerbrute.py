"""
Active Directory Kerberos username enumeration.
Classified as destructive: false. Belongs to profile 'ad-network'.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.kerbrute import execute as kb_execute
from tradecraft.adapters.kerbrute import parse as kb_parse
from tradecraft.tools.base import Tool


class Kerbrute(Tool):
    tool_id = "kerbrute"

    def run(
        self,
        target: str,
        domain: str,
        wordlist: str = "",
        safe: bool = True,
    ) -> Dict[str, Any]:
        raw = kb_execute.execute(
            target=target,
            domain=domain,
            wordlist=wordlist,
            safe=safe,
        )
        parsed = kb_parse.parse_kerbrute_result(raw)

        if raw.usernames:
            parsed["_full_evidence"] = {
                "target": raw.target,
                "domain": raw.domain,
                "total_users_found": len(raw.usernames),
                "usernames": raw.usernames,
                "raw_stdout": raw.stdout,
            }

        return parsed

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        host = kb_parse.normalize_target_host(target)
        return host, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = params.get("target", "")
        users = result.get("usernames", [])
        if not target or not users:
            return []

        host, port = kb_parse.parse_host_port(target, default_port=88)
        fact: Dict[str, Any] = {
            "host": host,
            "port": port,
            "ad_domain": result.get("domain", ""),
            "ad_valid_usernames_count": len(users),
        }

        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]

        return [fact]
