"""
destructive: true -- every call sends one real
write to a later workflow step (see
config/tools/workflow_step_bypass_probe.yaml).
"""
from __future__ import annotations

import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from tradecraft.adapters.workflow_step_bypass_probe import execute as workflow_execute
from tradecraft.adapters.workflow_step_bypass_probe import parse as workflow_parse
from tradecraft.tools.base import Tool


class WorkflowStepBypassProbe(Tool):
    tool_id = "workflow_step_bypass_probe"

    def run(
        self,
        target: str,
        method: str = "POST",
        body: Optional[str] = None,
        headers: Optional[str] = None,
        success_marker: Optional[str] = None,
        timeout: int = 10,
    ) -> Dict[str, Any]:
        raw = workflow_execute.execute(
            target=target,
            method=method,
            body=body,
            headers=headers,
            success_marker=success_marker,
            timeout=timeout,
        )
        result = workflow_parse.parse(raw)
        if result.get("step_bypass_suspected"):
            result["_full_evidence"] = dict(result)
        return result

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        parsed = urllib.parse.urlsplit(target if "://" in target else f"https://{target}")
        host = parsed.hostname or target
        return host, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        # Only a confirmed acceptance becomes a fact; an unconfirmed 2xx may
        # just be an endpoint that always returns 200.
        if result.get("classification") != "accepted_confirmed":
            return []
        target = result.get("target", "") or params.get("target", "")
        parsed = urllib.parse.urlsplit(target if "://" in target else f"https://{target}")
        host = parsed.hostname or target
        if not host:
            return []
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        fact: Dict[str, Any] = {
            "host": host,
            "port": port,
            "vulnerability": (
                "Workflow step bypass: later step accepted directly, skipping the preceding gated step"
            ),
            "severity": "high",
        }
        evidence_id = result.get("evidence_id")
        if evidence_id:
            fact["evidence"] = evidence_id
        return [fact]
