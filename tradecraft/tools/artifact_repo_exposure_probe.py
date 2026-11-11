"""
Artifact Repository Exposure Probe tool: non-destructive verification of
unauthenticated access on Nexus, Artifactory, and Harbor's own REST APIs.
Glues config/tools/artifact_repo_exposure_probe.yaml to
tradecraft.adapters.artifact_repo_exposure_probe.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from tradecraft.adapters.artifact_repo_exposure_probe.execute import execute as repo_execute
from tradecraft.adapters.artifact_repo_exposure_probe.parse import parse as repo_parse
from tradecraft.tools.base import Tool


class ArtifactRepoExposureProbe(Tool):
    tool_id = "artifact_repo_exposure_probe"

    def run(
        self,
        target: str,
        service: str = "auto",
        repository: Optional[str] = None,
        timeout: int = 10,
    ) -> Dict[str, Any]:
        result = repo_execute(target=target, service=service, repository=repository, timeout=timeout)
        parsed = repo_parse(result)

        full_evidence: Dict[str, Any] = {
            "target": target,
            "vulnerable": result.vulnerable,
            "summary": result.summary,
            "error": result.error,
        }
        if result.nexus is not None:
            full_evidence["nexus"] = {
                "connected": result.nexus.connected,
                "is_nexus": result.nexus.is_nexus,
                "unauthenticated_access": result.nexus.unauthenticated_access,
                "vulnerable": result.nexus.vulnerable,
                "status": result.nexus.status,
                "nexus_version": result.nexus.nexus_version,
                "repository_checked": result.nexus.repository_checked,
                "components_exposed": result.nexus.components_exposed,
                "error": result.nexus.error,
            }
        if result.artifactory is not None:
            full_evidence["artifactory"] = {
                "connected": result.artifactory.connected,
                "is_artifactory": result.artifactory.is_artifactory,
                "unauthenticated_access": result.artifactory.unauthenticated_access,
                "vulnerable": result.artifactory.vulnerable,
                "status": result.artifactory.status,
                "repositories_exposed": result.artifactory.repositories_exposed,
                "repository_names": list(result.artifactory.repository_names),
                "error": result.artifactory.error,
            }
        if result.harbor is not None:
            full_evidence["harbor"] = {
                "connected": result.harbor.connected,
                "is_harbor": result.harbor.is_harbor,
                "unauthenticated_access": result.harbor.unauthenticated_access,
                "vulnerable": result.harbor.vulnerable,
                "status": result.harbor.status,
                "harbor_version": result.harbor.harbor_version,
                "public_project_count": result.harbor.public_project_count,
                "unauth_project_count": result.harbor.unauth_project_count,
                "error": result.harbor.error,
            }

        parsed["_full_evidence"] = full_evidence
        return parsed

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        return target, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = params.get("target", "")
        facts: List[Dict[str, Any]] = []

        nexus_info = result.get("nexus")
        if nexus_info and nexus_info.get("connected"):
            fact: Dict[str, Any] = {"host": target, "port": 443, "service": "nexus", "state": "open"}
            if nexus_info.get("nexus_version"):
                fact["version"] = nexus_info["nexus_version"]
            if nexus_info.get("vulnerable"):
                fact["vulnerability"] = "Unauthenticated Nexus Component Listing Access"
                fact["severity"] = "high"
            facts.append(fact)

        artifactory_info = result.get("artifactory")
        if artifactory_info and artifactory_info.get("connected"):
            fact = {"host": target, "port": 443, "service": "artifactory", "state": "open"}
            if artifactory_info.get("vulnerable"):
                fact["vulnerability"] = "Unauthenticated Artifactory Repository Listing Access"
                fact["severity"] = "high"
            facts.append(fact)

        harbor_info = result.get("harbor")
        if harbor_info and harbor_info.get("connected"):
            fact = {"host": target, "port": 443, "service": "harbor", "state": "open"}
            if harbor_info.get("harbor_version"):
                fact["version"] = harbor_info["harbor_version"]
            if harbor_info.get("vulnerable"):
                fact["vulnerability"] = "Harbor Private Project Over-Exposure"
                fact["severity"] = "high"
            facts.append(fact)

        return facts
