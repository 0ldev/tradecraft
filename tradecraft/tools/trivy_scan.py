"""
Read-only vulnerability scan of one
container image reference via Aqua Trivy (`trivy image`). Classified as
destructive: false -- trivy only reads the image and reports what it
finds; it never pushes or changes the image or the registry. Belongs to
profiles 'cloud' and 'kubernetes'.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.trivy_scan import execute as trivy_execute
from tradecraft.adapters.trivy_scan import parse as trivy_parse
from tradecraft.tools.base import Tool


class TrivyScan(Tool):
    tool_id = "trivy_scan"

    def is_available(self) -> bool:
        return trivy_execute.is_available()

    def run(
        self,
        target: str,
        credential: str = "",
    ) -> Dict[str, Any]:
        raw = trivy_execute.execute(target=target, credential=credential)
        result = trivy_parse.parse_trivy_result(raw)
        report = result.pop("_report", None)
        if report is not None:
            result["_full_evidence"] = trivy_parse.build_full_evidence(target, report)
        return result

    def extract_evidence(
        self, params: Dict[str, Any], result: Dict[str, Any]
    ) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        return target, full

    def extract_facts(
        self, params: Dict[str, Any], result: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        # An image reference is not a host:port, so no host/port facts are
        # derived from it. The full report is still filed as evidence under
        # the image reference.
        return []
