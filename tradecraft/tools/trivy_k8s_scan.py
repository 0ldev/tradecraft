"""
Read-only security scan of one live Kubernetes cluster via Aqua Trivy
(`trivy k8s`). Reports CVEs in running workload images and Kubernetes
misconfigurations. Classified as destructive: false -- the scan reads
cluster state and reports what it finds; it applies no fixes and writes no
resources, and always runs with Trivy's node collector disabled (that
collector otherwise deploys its own Job and namespace into the cluster).
Belongs to profile 'kubernetes'.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.trivy_k8s_scan import execute as trivy_k8s_execute
from tradecraft.adapters.trivy_k8s_scan import parse as trivy_k8s_parse
from tradecraft.tools.base import Tool


class TrivyK8sScan(Tool):
    tool_id = "trivy_k8s_scan"

    def is_available(self) -> bool:
        return trivy_k8s_execute.is_available()

    def run(
        self,
        kubeconfig: str,
        namespace: str = "",
        context: str = "",
    ) -> Dict[str, Any]:
        raw = trivy_k8s_execute.execute(kubeconfig=kubeconfig, namespace=namespace, context=context)
        result = trivy_k8s_parse.parse_trivy_k8s_result(raw)
        report = result.pop("_report", None)
        if report is not None:
            result["_full_evidence"] = trivy_k8s_parse.build_full_evidence(_scope_key(result), report)
        return result

    def extract_evidence(
        self, params: Dict[str, Any], result: Dict[str, Any]
    ) -> Tuple[str, Any] | None:
        full = result.pop("_full_evidence", None)
        if full is None:
            return None
        return _scope_key(result), full

    def extract_facts(
        self, params: Dict[str, Any], result: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        # Cluster findings are not host:port observations, so no facts are
        # derived. The full report is filed as evidence under the cluster scope.
        return []


def _scope_key(result: Dict[str, Any]) -> str:
    return f"k8s:{result.get('context', 'default')}/{result.get('namespace', 'all')}"
