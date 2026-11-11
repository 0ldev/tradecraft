"""
Passive, read-only Kubernetes
cluster vulnerability discovery via kube-hunter's remote mode.
Classified as destructive: false. Belongs to profile 'kubernetes'.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.kube_hunter_enum import execute as kh_execute
from tradecraft.adapters.kube_hunter_enum import parse as kh_parse
from tradecraft.tools.base import Tool

# Facts are keyed by (host, port). A /24 can surface many services; cap
# the number written to the fact store per call.
MAX_FACTS = 100

_SEVERITIES = ("critical", "high", "medium", "low")


class KubeHunterEnum(Tool):
    tool_id = "kube_hunter_enum"

    def is_available(self) -> bool:
        return kh_execute.find_kube_hunter_binary() is not None

    def run(
        self,
        target: str,
        token: str = "",
        cve_hunting: bool = False,
    ) -> Dict[str, Any]:
        raw = kh_execute.execute(
            target=target,
            token=token,
            cve_hunting=cve_hunting,
        )
        parsed = kh_parse.parse_kube_hunter_enum_result(raw)

        if raw.stdout or raw.stderr:
            # The full JSON report is the authoritative record; the
            # model-facing view is capped, so keep the complete transcript
            # as evidence.
            parsed["_full_evidence"] = {
                "target": raw.target,
                "target_kind": raw.target_kind,
                "mode": "passive",
                "report": kh_parse.cap_evidence(raw.stdout),
                "raw_stderr": kh_parse.cap_evidence(raw.stderr),
            }

        return parsed

    def extract_evidence(
        self, params: Dict[str, Any], result: Dict[str, Any]
    ) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        _, value, error = kh_parse.parse_target(target)
        return (value or target), full

    def extract_facts(
        self, params: Dict[str, Any], result: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        if result.get("status") != "success":
            return []

        services = result.get("services") or []
        vulnerabilities = result.get("vulnerabilities") or []

        vulnerabilities_by_location: Dict[
            Tuple[str, int], List[Dict[str, Any]]
        ] = {}
        for vulnerability in vulnerabilities:
            host, port = kh_parse.parse_host_port(
                vulnerability.get("location", "")
            )
            if not host or port is None:
                continue
            vulnerabilities_by_location.setdefault((host, port), []).append(
                vulnerability
            )

        facts: List[Dict[str, Any]] = []
        seen: set[Tuple[str, int]] = set()

        for service in services:
            host, port = kh_parse.parse_host_port(service.get("location", ""))
            if not host or port is None:
                continue
            key = (host, port)
            if key in seen:
                continue
            seen.add(key)
            facts.append(
                self._service_fact(
                    host,
                    port,
                    str(service.get("service") or "unknown"),
                    vulnerabilities_by_location.get(key, []),
                    result,
                )
            )
            if len(facts) >= MAX_FACTS:
                return facts

        # A vulnerability can reference a location that kube-hunter did
        # not separately list as a service; still record it.
        for (host, port), location_vulns in sorted(
            vulnerabilities_by_location.items()
        ):
            if (host, port) in seen:
                continue
            facts.append(
                self._service_fact(
                    host,
                    port,
                    "unknown",
                    location_vulns,
                    result,
                )
            )
            if len(facts) >= MAX_FACTS:
                break

        return facts

    @staticmethod
    def _service_fact(
        host: str,
        port: int,
        service_name: str,
        vulnerabilities: List[Dict[str, Any]],
        result: Dict[str, Any],
    ) -> Dict[str, Any]:
        severity_counts = {severity: 0 for severity in _SEVERITIES}
        for vulnerability in vulnerabilities:
            severity = (
                str(vulnerability.get("severity", "")).strip().lower()
            )
            if severity in severity_counts:
                severity_counts[severity] += 1

        fact: Dict[str, Any] = {
            "host": host,
            "port": port,
            "protocol": "k8s",
            "k8s_service": service_name,
            "k8s_vulnerable": bool(vulnerabilities),
            "k8s_vulnerability_count": len(vulnerabilities),
            "k8s_critical_count": severity_counts["critical"],
            "k8s_high_count": severity_counts["high"],
            "k8s_medium_count": severity_counts["medium"],
            "k8s_low_count": severity_counts["low"],
        }
        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]
        return fact
