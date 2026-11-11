"""
SQL injection authentication bypass probing on login forms.
Classified as destructive: true.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.sqli_login import execute as sqli_execute
from tradecraft.adapters.sqli_login import parse as sqli_parse
from tradecraft.tools.base import Tool


class SqliLogin(Tool):
    tool_id = "sqli_login"

    def run(
        self,
        target: str,
        username_field: str = "",
        password_field: str = "",
        login_path: str = "",
    ) -> Dict[str, Any]:
        raw = sqli_execute.execute(
            target=target,
            username_field=username_field,
            password_field=password_field,
            login_path=login_path,
        )
        parsed = sqli_parse.parse_sqli_login_result(raw)

        if parsed.get("success"):
            parsed["_full_evidence"] = {
                "target": parsed.get("target"),
                "login_url": parsed.get("login_url"),
                "auth_type": parsed.get("auth_type"),
                "token": parsed.get("token"),
                "payload_used": parsed.get("payload_used"),
                "field_used": parsed.get("field_used"),
            }

        return parsed

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        host, _ = sqli_parse.parse_host_port(target)
        return host, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = params.get("target", "")
        if not target or not result.get("success"):
            return []

        host, port = sqli_parse.parse_host_port(target)
        fact: Dict[str, Any] = {
            "host": host,
            "port": port,
            "sqli_login_bypass": True,
        }

        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]

        return [fact]
