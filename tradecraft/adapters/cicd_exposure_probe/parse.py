"""
Parsing logic for cicd_exposure_probe results. Pure functions, no I/O.
"""
from __future__ import annotations

from typing import Any, Dict, List

from tradecraft.adapters.cicd_exposure_probe.execute import CicdExposureResult


def parse(result: CicdExposureResult) -> Dict[str, Any]:
    output: Dict[str, Any] = {
        "target": result.target,
        "vulnerable": result.vulnerable,
        "summary": result.summary,
        "error": result.error,
    }

    findings: List[str] = []

    if result.argocd is not None:
        output["argocd"] = {
            "connected": result.argocd.connected,
            "is_argocd": result.argocd.is_argocd,
            "unauthenticated_access": result.argocd.unauthenticated_access,
            "vulnerable": result.argocd.vulnerable,
            "status": result.argocd.status,
            "argocd_version": result.argocd.argocd_version,
            "applications_exposed": result.argocd.applications_exposed,
            "error": result.argocd.error,
        }
        if result.argocd.vulnerable:
            findings.append(
                f"Unauthenticated Argo CD application-list access ({result.argocd.applications_exposed} apps exposed)"
            )

    if result.teamcity is not None:
        output["teamcity"] = {
            "connected": result.teamcity.connected,
            "is_teamcity": result.teamcity.is_teamcity,
            "unauthenticated_access": result.teamcity.unauthenticated_access,
            "vulnerable": result.teamcity.vulnerable,
            "status": result.teamcity.status,
            "teamcity_version": result.teamcity.teamcity_version,
            "guest_projects_exposed": result.teamcity.guest_projects_exposed,
            "error": result.teamcity.error,
        }
        if result.teamcity.vulnerable:
            findings.append(
                f"TeamCity guest-login access enabled ({result.teamcity.guest_projects_exposed} projects exposed)"
            )

    output["findings"] = findings
    return output
