"""
Tool glue for cloud_metadata_credential_probe: extracts temporary cloud credentials
from a target's IMDS endpoint via an SSRF injection sink in its own backend.
Glues config/tools/cloud_metadata_credential_probe.yaml to
tradecraft.adapters.cloud_metadata_credential_probe.
"""
from __future__ import annotations

from typing import Any, Dict, List

from tradecraft.adapters.cloud_metadata_credential_probe.execute import execute as probe_execute
from tradecraft.adapters.cloud_metadata_credential_probe.parse import parse as probe_parse
from tradecraft.adapters.http_request.parse import host_port_from_url
from tradecraft.tools.base import Tool


class CloudMetadataCredentialProbe(Tool):
    tool_id = "cloud_metadata_credential_probe"

    def run(
        self,
        target: str,
        provider: str = "aws",
        inject_location: str = "url_param",
        method: str = "",
        json_body_template: str = "",
        header_name: str = "",
        role_name: str = "",
        timeout: int = 10,
    ) -> Dict[str, Any]:
        raw = probe_execute(
            target=target,
            provider=provider,
            inject_location=inject_location,
            method=method,
            json_body_template=json_body_template,
            header_name=header_name,
            role_name=role_name,
            timeout=timeout,
        )
        return probe_parse(raw)

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
            "service": f"{result.get('provider', 'cloud')}-metadata",
        }

        if result.get("credentials_obtained"):
            provider_label = result.get("provider", "cloud").upper()
            role_desc = f" for role '{result['role_name']}'" if result.get("role_name") else ""
            fact["credentials_obtained"] = True
            fact["cloud_provider"] = result.get("provider")
            fact["vulnerability"] = f"IMDS temporary credential exposure via SSRF{role_desc} ({provider_label})"
            fact["severity"] = "critical"
            if result.get("role_name"):
                fact["role"] = result["role_name"]
        else:
            fact["imds_tested"] = True

        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]

        return [fact]
