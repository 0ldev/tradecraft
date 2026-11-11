"""
Parsing logic for artifact_repo_exposure_probe results. Pure functions, no I/O.
"""
from __future__ import annotations

from typing import Any, Dict, List

from tradecraft.adapters.artifact_repo_exposure_probe.execute import ArtifactRepoExposureResult


def parse(result: ArtifactRepoExposureResult) -> Dict[str, Any]:
    output: Dict[str, Any] = {
        "target": result.target,
        "vulnerable": result.vulnerable,
        "summary": result.summary,
        "error": result.error,
    }

    findings: List[str] = []

    if result.nexus is not None:
        output["nexus"] = {
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
        if result.nexus.vulnerable:
            findings.append(
                f"Unauthenticated Nexus component listing on repository '{result.nexus.repository_checked}' "
                f"({result.nexus.components_exposed} components exposed)"
            )

    if result.artifactory is not None:
        output["artifactory"] = {
            "connected": result.artifactory.connected,
            "is_artifactory": result.artifactory.is_artifactory,
            "unauthenticated_access": result.artifactory.unauthenticated_access,
            "vulnerable": result.artifactory.vulnerable,
            "status": result.artifactory.status,
            "repositories_exposed": result.artifactory.repositories_exposed,
            "error": result.artifactory.error,
        }
        if result.artifactory.vulnerable:
            findings.append(
                f"Unauthenticated Artifactory repository listing ({result.artifactory.repositories_exposed} repos exposed)"
            )

    if result.harbor is not None:
        output["harbor"] = {
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
        if result.harbor.vulnerable:
            findings.append(
                f"Harbor exposes {result.harbor.unauth_project_count} projects unauthenticated vs. "
                f"{result.harbor.public_project_count} actually public"
            )

    output["findings"] = findings
    return output
