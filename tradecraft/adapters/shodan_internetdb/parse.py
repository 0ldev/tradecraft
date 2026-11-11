"""
Parsing logic for Shodan InternetDB query results.
"""
from __future__ import annotations

from typing import Any, Dict, List

from tradecraft.adapters.shodan_internetdb.execute import RawShodanResult


def parse_one(result: RawShodanResult) -> Dict[str, Any]:
    if result.error:
        return {"ip": result.ip, "error": result.error}
    if not result.found:
        return {"ip": result.ip, "known_to_shodan": False}
    body = result.body or {}
    return {
        "ip": result.ip,
        "known_to_shodan": True,
        "ports": body.get("ports", []),
        "hostnames": body.get("hostnames", []),
        "cpes": body.get("cpes", []),
        "vulns": body.get("vulns", []),
        "tags": body.get("tags", []),
    }


def parse_all(results: List[RawShodanResult]) -> List[Dict[str, Any]]:
    return [parse_one(r) for r in results]
