"""
Parsing logic for anonymous service probe results.
Pure functions, no I/O.
"""
from __future__ import annotations

from typing import Any, Dict, List

from tradecraft.adapters.anon_service_probe.execute import AnonServiceResult


def parse(result: AnonServiceResult) -> Dict[str, Any]:
    """Formats AnonServiceResult into dictionary suitable for model context
    and evidence persistence."""
    output: Dict[str, Any] = {
        "target": result.target,
        "host": result.host,
        "vulnerable": result.vulnerable,
        "summary": result.summary,
    }

    if result.error:
        output["error"] = result.error

    findings: List[str] = []

    if result.ftp:
        output["ftp"] = {
            "port": result.ftp.port,
            "connected": result.ftp.connected,
            "status": result.ftp.status,
            "banner": result.ftp.banner,
            "anonymous_login": result.ftp.anonymous_login,
            "server_response": result.ftp.server_response,
        }
        if result.ftp.error:
            output["ftp"]["error"] = result.ftp.error
        if result.ftp.vulnerable:
            findings.append(f"FTP Anonymous Login Permitted on {result.host}:{result.ftp.port}")

    if result.mysql:
        output["mysql"] = {
            "port": result.mysql.port,
            "connected": result.mysql.connected,
            "status": result.mysql.status,
            "server_version": result.mysql.server_version,
            "auth_plugin": result.mysql.auth_plugin,
            "empty_root_password": result.mysql.empty_root_password,
            "error_code": result.mysql.error_code,
            "server_message": result.mysql.server_message,
        }
        if result.mysql.error:
            output["mysql"]["error"] = result.mysql.error
        if result.mysql.vulnerable:
            findings.append(f"MySQL Unauthenticated / Empty Root Password on {result.host}:{result.mysql.port}")

    output["findings"] = findings
    return output
