"""
CI/CD Exposure Probe tool: non-destructive verification of unauthenticated
access on Argo CD and TeamCity (guest login). Glues
config/tools/cicd_exposure_probe.yaml to tradecraft.adapters.cicd_exposure_probe.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.cicd_exposure_probe.execute import execute as cicd_execute
from tradecraft.adapters.cicd_exposure_probe.parse import parse as cicd_parse
from tradecraft.tools.base import Tool


class CicdExposureProbe(Tool):
    tool_id = "cicd_exposure_probe"

    def run(self, target: str, service: str = "auto", timeout: int = 10) -> Dict[str, Any]:
        result = cicd_execute(target=target, service=service, timeout=timeout)
        parsed = cicd_parse(result)

        full_evidence: Dict[str, Any] = {
            "target": target,
            "vulnerable": result.vulnerable,
            "summary": result.summary,
            "error": result.error,
        }
        if result.argocd is not None:
            full_evidence["argocd"] = {
                "connected": result.argocd.connected,
                "is_argocd": result.argocd.is_argocd,
                "unauthenticated_access": result.argocd.unauthenticated_access,
                "vulnerable": result.argocd.vulnerable,
                "status": result.argocd.status,
                "argocd_version": result.argocd.argocd_version,
                "applications_exposed": result.argocd.applications_exposed,
                "application_names": list(result.argocd.application_names),
                "error": result.argocd.error,
            }
        if result.teamcity is not None:
            full_evidence["teamcity"] = {
                "connected": result.teamcity.connected,
                "is_teamcity": result.teamcity.is_teamcity,
                "unauthenticated_access": result.teamcity.unauthenticated_access,
                "vulnerable": result.teamcity.vulnerable,
                "status": result.teamcity.status,
                "teamcity_version": result.teamcity.teamcity_version,
                "guest_projects_exposed": result.teamcity.guest_projects_exposed,
                "project_names": list(result.teamcity.project_names),
                "error": result.teamcity.error,
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

        argocd_info = result.get("argocd")
        if argocd_info and argocd_info.get("connected"):
            fact: Dict[str, Any] = {"host": target, "port": 443, "service": "argocd", "state": "open"}
            if argocd_info.get("argocd_version"):
                fact["version"] = argocd_info["argocd_version"]
            if argocd_info.get("vulnerable"):
                fact["vulnerability"] = "Unauthenticated Argo CD Application-List Access"
                fact["severity"] = "high"
            facts.append(fact)

        teamcity_info = result.get("teamcity")
        if teamcity_info and teamcity_info.get("connected"):
            fact = {"host": target, "port": 443, "service": "teamcity", "state": "open"}
            if teamcity_info.get("teamcity_version"):
                fact["version"] = teamcity_info["teamcity_version"]
            if teamcity_info.get("vulnerable"):
                fact["vulnerability"] = "TeamCity Guest-Login Access Enabled"
                fact["severity"] = "high"
            facts.append(fact)

        return facts
