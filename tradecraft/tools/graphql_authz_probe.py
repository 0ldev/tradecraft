"""
GraphQL Authorization Probe tool: tests ID-shaped Query fields for
Broken Object Level Authorization (BOLA) by comparing a privileged
request's result against an unauthenticated request's result for the
same object. Queries only, never mutations. Glues
config/tools/graphql_authz_probe.yaml to tradecraft.adapters.graphql_authz_probe.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from tradecraft.adapters.graphql_authz_probe.execute import execute as authz_execute
from tradecraft.adapters.graphql_authz_probe.parse import parse as authz_parse
from tradecraft.tools.base import Tool


class GraphqlAuthzProbe(Tool):
    tool_id = "graphql_authz_probe"

    def run(
        self,
        target: str,
        sample_id: str,
        schema_json: Optional[str] = None,
        headers_privileged: Optional[str] = None,
        headers_unauth: Optional[str] = None,
        timeout: int = 10,
    ) -> Dict[str, Any]:
        result = authz_execute(
            target=target, sample_id=sample_id, schema_json=schema_json,
            headers_privileged=headers_privileged, headers_unauth=headers_unauth, timeout=timeout,
        )
        return authz_parse(result)

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not result.get("vulnerable"):
            return []
        target = params.get("target", "")
        parsed = urlparse(target)
        host = parsed.hostname or target
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        vulnerable_fields = [f["field_name"] for f in result.get("fields_checked", []) if f.get("vulnerable")]
        return [{
            "host": host,
            "port": port,
            "vulnerability": f"GraphQL BOLA: query field(s) {', '.join(vulnerable_fields)} resolve without authentication",
            "severity": "high",
        }]
