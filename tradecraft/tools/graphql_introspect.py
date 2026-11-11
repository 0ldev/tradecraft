"""
GraphQL Introspect tool: checks if GraphQL introspection is enabled on an endpoint.
Glues config/tools/graphql_introspect.yaml to tradecraft.adapters.graphql_introspect.
"""
from __future__ import annotations

from urllib.parse import urlparse
from typing import Any, Dict, List, Tuple

from tradecraft.adapters.graphql_introspect import execute as graphql_execute
from tradecraft.adapters.graphql_introspect import parse as graphql_parse
from tradecraft.tools.base import Tool


class GraphqlIntrospect(Tool):
    tool_id = "graphql_introspect"

    def run(self, url: str) -> Dict[str, Any]:
        raw = graphql_execute.execute(url)
        parsed = graphql_parse.parse_introspection(raw)
        res: Dict[str, Any] = {"url": url, **parsed}
        if raw.body:
            res["_full_evidence"] = {"url": url, "response": raw.body}
        return res

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        url = params.get("url", "")
        full = result.pop("_full_evidence", None)
        if not url or full is None:
            return None
        parsed = urlparse(url)
        canonical_target = parsed.netloc or url
        return canonical_target, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not result.get("introspection_enabled"):
            return []
        url = params.get("url", "")
        parsed = urlparse(url)
        host = parsed.hostname or url
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        fact: Dict[str, Any] = {
            "host": host,
            "port": port,
            "graphql_introspection": "enabled",
        }
        if result.get("type_count"):
            fact["graphql_type_count"] = result["type_count"]
        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]
        return [fact]
