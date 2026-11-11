from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from tradecraft.adapters.docker_api_probe.execute import execute as docker_execute
from tradecraft.adapters.docker_api_probe.parse import parse as docker_parse
from tradecraft.tools.base import Tool


class DockerApiProbe(Tool):
    tool_id = "docker_api_probe"

    def run(self, target: str, timeout: int = 10) -> Dict[str, Any]:
        raw = docker_execute(target=target, timeout=timeout)
        parsed = docker_parse(raw)

        parsed["_full_evidence"] = {
            "target": raw.target,
            "host": raw.host,
            "port": raw.port,
            "version_info": raw.version_info,
            "info": raw.info,
            "containers": raw.containers,
        }
        return parsed

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        host = result.get("host") or params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not host or full is None:
            return None
        return host, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not result.get("reachable"):
            return []
        fact: Dict[str, Any] = {
            "host": result.get("host") or params.get("target", ""),
            "port": result.get("port", 2375),
            "service": "docker-api",
            "state": "open",
            "vulnerability": "Unauthenticated Docker Engine API access",
            "severity": "critical",
        }
        if result.get("docker_version"):
            fact["version"] = result["docker_version"]
        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]
        return [fact]
