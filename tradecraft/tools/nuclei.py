from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.nuclei import execute as nuclei_execute
from tradecraft.adapters.nuclei import parse as nuclei_parse
from tradecraft.tools.base import Tool


class Nuclei(Tool):
    tool_id = "nuclei"

    def run(
        self,
        target: str,
        tags: str = "cve,misconfig,exposure,tech",
        severity: str = "low,medium,high,critical",
        templates: str = "",
        limit: int = 25,
    ) -> Dict[str, Any]:
        raw = nuclei_execute.execute(
            target=target,
            tags=tags,
            severity=severity,
            templates=templates,
        )
        if raw.error and not raw.timed_out:
            return {
                "target": target,
                "findings": [],
                "error": raw.error,
            }

        parsed = nuclei_parse.parse_nuclei_output(raw.stdout)
        findings = parsed.get("findings", [])

        res: Dict[str, Any] = {
            "target": target,
            "total_findings": len(findings),
            "worst_severity": parsed.get("worst_severity"),
            "severities_count": parsed.get("severities_count", {}),
        }
        if raw.timed_out:
            res["timed_out"] = True
            res["timeout_seconds"] = raw.timeout_seconds
            res["timeout_note"] = (
                "The scan was stopped at its timeout, so these findings are partial. "
                "A template that did not finish is not reflected here: an empty or "
                "short list does not mean the target is clean."
            )
            if not findings and not raw.stdout.strip():
                # Nothing at all came back before the kill; report it as a failure.
                res["error"] = raw.error

        effective_limit = max(1, limit) if limit else 25

        # Smart tiered selection:
        # 1. Critical & High findings are highest-priority signal and are always preserved.
        # 2. Lower-severity findings (medium, low, info) fill remaining slots up to limit.
        high_crit_findings = [
            f for f in findings if f.get("severity", "").lower() in ("critical", "high")
        ]
        other_findings = [
            f for f in findings if f.get("severity", "").lower() not in ("critical", "high")
        ]

        if len(findings) <= effective_limit:
            selected_findings = findings
            omitted = 0
        else:
            if len(high_crit_findings) >= effective_limit:
                # Always retain all critical and high findings even if they exceed limit
                selected_findings = high_crit_findings
            else:
                remaining_slots = effective_limit - len(high_crit_findings)
                selected_findings = high_crit_findings + other_findings[:remaining_slots]
            omitted = len(findings) - len(selected_findings)

        res["findings"] = selected_findings
        if omitted > 0:
            res["omitted_findings"] = omitted
            res["note"] = (
                f"{omitted} lower-severity findings omitted to conserve context "
                f"(all {len(high_crit_findings)} critical/high findings retained). "
                "Use read_evidence to inspect all."
            )

        res["_full_evidence"] = {
            "target": target,
            "total_findings": len(findings),
            "worst_severity": parsed.get("worst_severity"),
            "severities_count": parsed.get("severities_count", {}),
            "findings": findings,
            "timed_out": bool(raw.timed_out),
        }
        return res

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        host, _ = nuclei_parse.host_port_from_target(target)
        canonical_target = host if host else target
        return canonical_target, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = params.get("target", "")
        if not target:
            return []
        host, port = nuclei_parse.host_port_from_target(target)
        total_findings = result.get("total_findings", len(result.get("findings", [])))
        worst_sev = result.get("worst_severity")

        fact: Dict[str, Any] = {"host": host, "port": port}
        if total_findings > 0:
            fact["nuclei_findings_count"] = total_findings
        if worst_sev:
            fact["nuclei_worst_severity"] = worst_sev
        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]

        if len(fact) > 2:
            return [fact]
        return []
