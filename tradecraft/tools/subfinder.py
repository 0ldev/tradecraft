from __future__ import annotations

import urllib.parse
from typing import Any, Dict, List, Tuple

from tradecraft.adapters.subfinder import execute as subfinder_execute
from tradecraft.adapters.subfinder import parse as subfinder_parse
from tradecraft.tools.base import Tool


def _host_from_target(target: str) -> str:
    parsed = urllib.parse.urlsplit(target if "://" in target else f"//{target}")
    return parsed.hostname or target


class Subfinder(Tool):
    tool_id = "subfinder"

    def run(self, target: str) -> Dict[str, Any]:
        raw = subfinder_execute.execute(target)
        if raw.error:
            return {"target": target, "subdomains": [], "error": raw.error}
        subdomains = subfinder_parse.parse_subdomains(raw.stdout, target)
        result: Dict[str, Any] = {"target": target, "subdomains": subdomains}
        if subdomains:
            result["_full_evidence"] = {"target": target, "subdomains": subdomains}
        return result

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        return target, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = params.get("target", "")
        subdomains = result.get("subdomains", [])
        if not target or not subdomains:
            return []
        host = _host_from_target(target)
        # Subfinder is domain-wide passive enumeration, not a probe of any
        # real service -- port 0 is the sentinel this codebase already
        # uses for a fact with no real port (see tradecraft/tools/
        # interactsh.py). Reusing a real port number like 80 here would
        # risk this fact silently merging into (host, 80)'s record with
        # whatever a real HTTP-port-80 service tool (nmap_scan,
        # httpx_probe, ...) reports for the same apex.
        port = 0
        fact: Dict[str, Any] = {"host": host, "port": port, "subdomains_discovered": len(subdomains)}
        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]
        return [fact]
