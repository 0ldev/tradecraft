"""
No scope_param -- this tool queries public
package registries (npm/PyPI/Maven Central), never the client's own
infrastructure, so there is no network target to scope-check.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from tradecraft.adapters.dependency_confusion_probe import execute as dcp_execute
from tradecraft.adapters.dependency_confusion_probe import parse as dcp_parse
from tradecraft.tools.base import Tool


class DependencyConfusionProbe(Tool):
    tool_id = "dependency_confusion_probe"

    def run(self, packages: str, timeout: int = 10) -> Dict[str, Any]:
        raw = dcp_execute.execute(packages=packages, timeout=timeout)
        if raw.error:
            return {"error": raw.error}

        result = dcp_parse.parse(raw)
        result["_full_evidence"] = dict(result)
        return result

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        full = result.pop("_full_evidence", None)
        packages = params.get("packages", "")
        if not packages or full is None:
            return None
        first_package = packages.split(",")[0].strip().split(":")[0]
        return first_package or "dependency_confusion_probe", full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        # No (host, port) concept here -- squattable package names are
        # surfaced via log_finding/evidence instead of the FactStore.
        return []
