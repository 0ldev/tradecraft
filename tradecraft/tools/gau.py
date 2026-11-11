from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.gau import execute as gau_execute
from tradecraft.adapters.gau import parse as gau_parse
from tradecraft.tools.base import Tool


class Gau(Tool):
    tool_id = "gau"

    def run(
        self,
        target: str,
        include_subs: bool = True,
        providers: str = "wayback,otx",
    ) -> Dict[str, Any]:
        raw = gau_execute.execute(
            target=target,
            include_subs=include_subs,
            providers=providers,
        )
        if raw.error:
            return {
                "target": target,
                "urls": [],
                "endpoints": [],
                "subdomains": [],
                "parameters": [],
                "error": raw.error,
            }

        parsed = gau_parse.parse_gau_output(raw.stdout, base_domain=raw.target_domain)
        urls = parsed.get("urls", [])
        endpoints = parsed.get("endpoints", [])
        subdomains = parsed.get("subdomains", [])
        parameters = parsed.get("parameters", [])

        res: Dict[str, Any] = {
            "target": target,
            "total_urls": len(urls),
            "total_endpoints": len(endpoints),
            "total_subdomains": len(subdomains),
            "total_parameters": len(parameters),
            "subdomains": subdomains,
        }

        if len(urls) > 20:
            res["urls"] = urls[:20]
            res["omitted_urls"] = len(urls) - 20
            res["note"] = (
                f"{len(urls) - 20} more URLs omitted to conserve context. "
                "Do not use read_evidence for full dumps; use search_evidence(query=...) "
                "to query specific extensions (.php, .json), endpoints, or parameters."
            )
        else:
            res["urls"] = urls

        if len(endpoints) > 15:
            res["endpoints"] = endpoints[:15]
            res["omitted_endpoints"] = len(endpoints) - 15
        else:
            res["endpoints"] = endpoints

        if len(parameters) > 20:
            res["parameters"] = parameters[:20]
            res["omitted_parameters"] = len(parameters) - 20
        else:
            res["parameters"] = parameters

        res["_full_evidence"] = {
            "target": target,
            "total_urls": len(urls),
            "total_endpoints": len(endpoints),
            "total_subdomains": len(subdomains),
            "total_parameters": len(parameters),
            "urls": urls,
            "endpoints": endpoints,
            "subdomains": subdomains,
            "parameters": parameters,
        }
        return res

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        host, _ = gau_parse.host_port_from_target(target)
        canonical_target = host if host else target
        return canonical_target, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = params.get("target", "")
        if not target:
            return []
        host, _ = gau_parse.host_port_from_target(target)
        total_urls = result.get("total_urls", len(result.get("urls", [])))
        total_endpoints = result.get("total_endpoints", len(result.get("endpoints", [])))

        # Gau is passive URL discovery across the whole target, not a
        # probe of any real service -- port 0 is the sentinel this
        # codebase already uses for a fact with no real port (see
        # tradecraft/tools/interactsh.py). Reusing a real port number like 80
        # would risk this fact silently merging into (host, 80)'s record
        # with whatever a real HTTP-port-80 service tool (nmap_scan,
        # httpx_probe, ...) reports for the same apex.
        fact: Dict[str, Any] = {"host": host, "port": 0}
        if total_urls > 0:
            fact["passive_urls_discovered"] = total_urls
        if total_endpoints > 0:
            fact["endpoints_discovered"] = total_endpoints
        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]

        if len(fact) > 2:
            return [fact]
        return []
