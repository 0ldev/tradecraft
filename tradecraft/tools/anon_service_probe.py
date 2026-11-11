"""
Anonymous Service Probe tool: non-destructive verification of unauthenticated
access on FTP and MySQL.
Glues config/tools/anon_service_probe.yaml to tradecraft.adapters.anon_service_probe.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from tradecraft.adapters.anon_service_probe.execute import execute as anon_execute
from tradecraft.adapters.anon_service_probe.parse import parse as anon_parse
from tradecraft.tools.base import Tool


class AnonServiceProbe(Tool):
    tool_id = "anon_service_probe"

    def run(
        self,
        target: str,
        service: str = "auto",
        port: Optional[int] = None,
        timeout: int = 5,
    ) -> Dict[str, Any]:
        result = anon_execute(
            target=target,
            service=service,
            port=port,
            timeout=timeout,
        )
        parsed = anon_parse(result)

        full_evidence = {
            "target": target,
            "host": result.host,
            "vulnerable": result.vulnerable,
            "summary": result.summary,
            "error": result.error,
        }
        if result.ftp:
            full_evidence["ftp"] = {
                "port": result.ftp.port,
                "connected": result.ftp.connected,
                "banner": result.ftp.banner,
                "anonymous_login": result.ftp.anonymous_login,
                "vulnerable": result.ftp.vulnerable,
                "status": result.ftp.status,
                "server_response": result.ftp.server_response,
                "error": result.ftp.error,
            }
        if result.mysql:
            full_evidence["mysql"] = {
                "port": result.mysql.port,
                "connected": result.mysql.connected,
                "server_version": result.mysql.server_version,
                "auth_plugin": result.mysql.auth_plugin,
                "empty_root_password": result.mysql.empty_root_password,
                "vulnerable": result.mysql.vulnerable,
                "status": result.mysql.status,
                "error_code": result.mysql.error_code,
                "server_message": result.mysql.server_message,
                "error": result.mysql.error,
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
        host = result.get("host") or params.get("target", "")
        facts: List[Dict[str, Any]] = []

        ftp_info = result.get("ftp")
        if ftp_info and ftp_info.get("connected"):
            port = ftp_info.get("port", 21)
            fact: Dict[str, Any] = {"host": host, "port": port, "service": "ftp", "state": "open"}
            if ftp_info.get("anonymous_login"):
                fact["vulnerability"] = "FTP Anonymous Login Allowed"
                fact["severity"] = "high"
            facts.append(fact)

        mysql_info = result.get("mysql")
        if mysql_info and mysql_info.get("connected"):
            port = mysql_info.get("port", 3306)
            fact = {"host": host, "port": port, "service": "mysql", "state": "open"}
            if mysql_info.get("server_version"):
                fact["version"] = mysql_info["server_version"]
            if mysql_info.get("empty_root_password"):
                fact["vulnerability"] = "MySQL Unauthenticated Root Access (Empty Password)"
                fact["severity"] = "critical"
            facts.append(fact)

        return facts
