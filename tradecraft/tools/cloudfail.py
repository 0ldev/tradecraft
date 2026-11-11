from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.cloudfail.execute import (
    execute as run_cloudfail,
    normalize_target,
)
from tradecraft.adapters.cloudfail.parse import parse_cloudfail_output
from tradecraft.tools.base import Tool


class Cloudfail(Tool):
    tool_id = "cloudfail"

    def run(
        self,
        target: str,
        subdomains: str = "subdomains_top100.txt",
    ) -> Dict[str, Any]:
        raw = run_cloudfail(target=target, subdomains=subdomains)
        if raw.error:
            return {
                "target": target,
                "is_cloudflare": False,
                "origin_unmasked": False,
                "unmasked_origin_ips": [],
                "error": raw.error,
            }

        parsed = parse_cloudfail_output(raw.stdout, target=raw.target)

        res: Dict[str, Any] = {
            "target": target,
            "server_ip": parsed.get("server_ip", ""),
            "is_cloudflare": parsed.get("is_cloudflare", False),
            "origin_unmasked": parsed.get("origin_unmasked", False),
            "unmasked_origin_ips": parsed.get("unmasked_origin_ips", []),
        }

        unmasked_subs = parsed.get("unmasked_subdomains", [])
        if len(unmasked_subs) > 10:
            res["unmasked_subdomains"] = unmasked_subs[:10]
            res["omitted_unmasked_subdomains"] = len(unmasked_subs) - 10
        else:
            res["unmasked_subdomains"] = unmasked_subs

        cf_subs = parsed.get("cloudflare_subdomains", [])
        if len(cf_subs) > 10:
            res["cloudflare_subdomains"] = cf_subs[:10]
            res["omitted_cloudflare_subdomains"] = len(cf_subs) - 10
        else:
            res["cloudflare_subdomains"] = cf_subs

        if parsed.get("dnsdumpster_hosts"):
            res["dnsdumpster_hosts"] = parsed["dnsdumpster_hosts"][:5]

        res["_full_evidence"] = {
            "target": target,
            "server_ip": parsed.get("server_ip", ""),
            "is_cloudflare": parsed.get("is_cloudflare", False),
            "origin_unmasked": parsed.get("origin_unmasked", False),
            "unmasked_origin_ips": parsed.get("unmasked_origin_ips", []),
            "unmasked_subdomains": unmasked_subs,
            "cloudflare_subdomains": cf_subs,
            "dnsdumpster_hosts": parsed.get("dnsdumpster_hosts", []),
            "raw_stdout": raw.stdout,
        }
        return res

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        canonical = normalize_target(target)
        return canonical if canonical else target, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = params.get("target", "")
        if not target:
            return []
        host = normalize_target(target)
        is_cloudflare = result.get("is_cloudflare", False)
        unmasked_ips = result.get("unmasked_origin_ips", [])

        fact: Dict[str, Any] = {"host": host}
        if is_cloudflare:
            fact["cloudflare_protected"] = True
        if unmasked_ips:
            fact["origin_unmasked_ips"] = unmasked_ips
        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]

        if len(fact) > 1:
            return [fact]
        return []
