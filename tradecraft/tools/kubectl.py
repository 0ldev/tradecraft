"""
Kubernetes cluster and API server inspection. Classified as
destructive: false. Belongs to profile 'kubernetes'.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.kubectl import execute as k8s_execute
from tradecraft.adapters.kubectl import parse as k8s_parse
from tradecraft.tools.base import Tool


class Kubectl(Tool):
    tool_id = "kubectl"

    def run(
        self,
        target: str,
        token: str,
        namespace: str = "",
    ) -> Dict[str, Any]:
        raw = k8s_execute.execute(
            target=target,
            token=token,
            namespace=namespace,
        )
        parsed = k8s_parse.parse_kubectl_result(raw)

        if raw.permissions or raw.secrets:
            parsed["_full_evidence"] = {
                "target": raw.target,
                "namespace": raw.namespace,
                "overprivileged": raw.overprivileged,
                "permissions": raw.permissions,
                "secrets": raw.secrets,
            }

        return parsed

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        host, _ = k8s_parse.parse_host_port(target)
        return host, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = params.get("target", "")
        if not target or result.get("error"):
            return []

        host, port = k8s_parse.parse_host_port(target)
        fact: Dict[str, Any] = {
            "host": host,
            "port": port,
            "k8s_api_server": True,
            "k8s_overprivileged": result.get("overprivileged", False),
        }

        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]

        return [fact]
