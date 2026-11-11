"""
Pure local computation; no network access.
"""
from __future__ import annotations

from typing import Any, Dict

from tradecraft.adapters.subdomain_permute import execute as permute_execute
from tradecraft.adapters.subdomain_permute import parse as permute_parse
from tradecraft.tools.base import Tool


class SubdomainPermute(Tool):
    tool_id = "subdomain_permute"

    def run(self, target: str, seed_subdomains: str = "") -> Dict[str, Any]:
        raw = permute_execute.generate_candidates(target=target, seed_subdomains=seed_subdomains)
        return permute_parse.parse_permute_result(raw)
