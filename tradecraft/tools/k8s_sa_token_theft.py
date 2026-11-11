"""
Tool glue for k8s_sa_token_theft: extracts Kubernetes service account tokens
from container filesystem via file:// URI scheme injection in SSRF sinks.
Glues config/tools/k8s_sa_token_theft.yaml to tradecraft.adapters.k8s_sa_token_theft.
"""
from __future__ import annotations

from typing import Any, Dict, List

from tradecraft.adapters.http_request.parse import host_port_from_url
from tradecraft.adapters.k8s_sa_token_theft.execute import execute as theft_execute
from tradecraft.adapters.k8s_sa_token_theft.parse import parse as theft_parse
from tradecraft.tools.base import Tool


class K8sSaTokenTheft(Tool):
    tool_id = "k8s_sa_token_theft"

    def run(
        self,
        target: str,
        inject_location: str = "url_param",
        method: str = "",
        json_body_template: str = "",
        header_name: str = "",
        timeout: int = 10,
    ) -> Dict[str, Any]:
        raw = theft_execute(
            target=target,
            inject_location=inject_location,
            method=method,
            json_body_template=json_body_template,
            header_name=header_name,
            timeout=timeout,
        )
        return theft_parse(raw)

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = params.get("target", "")
        if not target or result.get("error"):
            return []

        host, port = host_port_from_url(target)
        if not host:
            return []

        fact: Dict[str, Any] = {
            "host": host,
            "port": port,
            "service": "k8s-pod-container",
        }

        if result.get("token_obtained"):
            fact["credentials_obtained"] = True
            fact["credential_type"] = "k8s_service_account_token"
            fact["severity"] = "critical"
            ns = result.get("namespace") or result.get("claims", {}).get("kubernetes.io", {}).get("namespace")
            sub = result.get("claims", {}).get("sub", "")
            ns_desc = f" in namespace '{ns}'" if ns else ""
            sub_desc = f" for '{sub}'" if sub else ""
            fact["vulnerability"] = (
                f"Kubernetes service account token exposure via file:// SSRF{sub_desc}{ns_desc}"
            )
            if ns:
                fact["k8s_namespace"] = ns
            if sub:
                fact["k8s_service_account"] = sub
        else:
            fact["k8s_token_ssrf_tested"] = True

        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]

        return [fact]
