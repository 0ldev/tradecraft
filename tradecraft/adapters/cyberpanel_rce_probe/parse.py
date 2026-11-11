"""
Pure parsing for cyberpanel_rce_probe (CVE-2024-51567 & CVE-2024-51378).
Extracts RCE verification results, reflected command output, and diagnostic
details. No I/O.
"""
from __future__ import annotations

from typing import Any, Dict, List

from tradecraft.adapters.cyberpanel_rce_probe.execute import CyberPanelEndpointResult, RawCyberPanelResult


def parse_cyberpanel_result(raw: RawCyberPanelResult) -> Dict[str, Any]:
    if raw.error:
        return {
            "target": raw.target,
            "vulnerable": False,
            "status": "error",
            "error": raw.error,
        }

    vulnerable_probe: Optional[CyberPanelEndpointResult] = None
    probes_summary: List[Dict[str, Any]] = []

    for probe in raw.probes:
        probes_summary.append({
            "base_url": probe.base_url,
            "endpoint": probe.endpoint,
            "method": probe.method,
            "status_code": probe.status_code,
            "error": probe.error,
        })
        if probe.is_vulnerable and not vulnerable_probe:
            vulnerable_probe = probe

    if vulnerable_probe:
        clean_snippet = vulnerable_probe.output_snippet.strip()
        summary = (
            f"CRITICAL VULNERABILITY: CyberPanel unauthenticated Remote Code Execution "
            f"(CVE-2024-51567 / CVE-2024-51378) confirmed on {vulnerable_probe.base_url}"
            f"{vulnerable_probe.endpoint} via {vulnerable_probe.method}."
        )
        return {
            "target": raw.target,
            "vulnerable": True,
            "status": "vulnerable",
            "summary": summary,
            "endpoint": vulnerable_probe.endpoint,
            "method": vulnerable_probe.method,
            "base_url": vulnerable_probe.base_url,
            "execution_proof": clean_snippet[:500],
            "cyberpanel_fingerprinted": raw.target_identified_as_cyberpanel,
            "probes_evaluated": probes_summary,
            "recommendation": (
                "Immediately upgrade CyberPanel to version 2.3.7 or apply official hotfixes from "
                "CyberPanel security advisories. Restrict port 8090 access to trusted administrative IPs."
            ),
        }

    # Not vulnerable
    if not raw.target_identified_as_cyberpanel and all(
        p.status_code in (404, None) for p in raw.probes
    ):
        summary = (
            "NOT_APPLICABLE: Target does not appear to run CyberPanel or management port (8090) is closed."
        )
        status = "not_applicable"
    else:
        summary = (
            f"SAFE: Target did not execute injected command across {len(raw.probes)} probed endpoint/method combination(s)."
        )
        status = "safe"

    return {
        "target": raw.target,
        "vulnerable": False,
        "status": status,
        "summary": summary,
        "cyberpanel_fingerprinted": raw.target_identified_as_cyberpanel,
        "probes_evaluated": probes_summary,
    }
