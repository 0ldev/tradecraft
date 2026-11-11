"""
Pure parsing for craftcms_transform_rce_probe (CVE-2025-32432 / Jan 2026 PoC).
Extracts vulnerability status, gadget reflection, and remediation advice.
No I/O.
"""
from __future__ import annotations

from typing import Any, Dict

from tradecraft.adapters.craftcms_transform_rce_probe.execute import RawCraftResult


def parse_craft_result(raw: RawCraftResult) -> Dict[str, Any]:
    if raw.error and raw.probe_status is None:
        return {
            "target": raw.target,
            "vulnerable": False,
            "status": "error",
            "error": raw.error,
        }

    if raw.gadget_triggered:
        summary = (
            f"CRITICAL VULNERABILITY: Craft CMS Pre-Auth Remote Code Execution (CVE-2025-32432) "
            f"confirmed on {raw.base_url}{raw.endpoint_path}. The endpoint unauthenticatedly accepted "
            f"and evaluated the Yii/Craft transform behavior object gadget chain."
        )
        return {
            "target": raw.target,
            "base_url": raw.base_url,
            "endpoint_path": raw.endpoint_path,
            "vulnerable": True,
            "cve": "CVE-2025-32432",
            "status": "vulnerable",
            "summary": summary,
            "craft_detected": raw.craft_detected,
            "action_accessible": raw.action_accessible,
            "probe_status": raw.probe_status,
            "evidence_snippet": raw.probe_response_snippet[:300],
            "recommendation": (
                "Upgrade Craft CMS immediately to patched releases (> 5.6.16, > 4.14.14, > 3.9.14). "
                "Block external unauthenticated POST access to /actions/assets/generate-transform at "
                "the reverse proxy or web application firewall."
            ),
        }

    if raw.action_accessible and raw.craft_detected:
        summary = (
            f"POTENTIALLY VULNERABLE: Craft CMS pre-auth generate-transform action endpoint ({raw.endpoint_path}) "
            f"is accessible (HTTP {raw.probe_status}) on {raw.base_url}, but did not directly execute the full "
            f"gadget chain in this diagnostic probe."
        )
        return {
            "target": raw.target,
            "base_url": raw.base_url,
            "endpoint_path": raw.endpoint_path,
            "vulnerable": False,
            "cve": "CVE-2025-32432",
            "status": "partial",
            "summary": summary,
            "craft_detected": raw.craft_detected,
            "action_accessible": raw.action_accessible,
            "probe_status": raw.probe_status,
            "evidence_snippet": raw.probe_response_snippet[:300],
            "recommendation": (
                "Verify Craft CMS version and ensure security updates (> 5.6.16, > 4.14.14, > 3.9.14) "
                "are applied."
            ),
        }

    if not raw.craft_detected and (raw.probe_status in (404, None)):
        summary = (
            f"NOT_APPLICABLE: Target does not appear to run Craft CMS or generate-transform actions "
            f"returned 404 on {raw.base_url}."
        )
        status = "not_applicable"
    else:
        summary = (
            f"SAFE: Craft CMS pre-auth generate-transform action was not reachable or rejected unauthenticated "
            f"requests (HTTP {raw.probe_status}) on {raw.base_url}."
        )
        status = "safe"

    return {
        "target": raw.target,
        "base_url": raw.base_url,
        "endpoint_path": raw.endpoint_path,
        "vulnerable": False,
        "cve": "CVE-2025-32432",
        "status": status,
        "summary": summary,
        "craft_detected": raw.craft_detected,
        "action_accessible": raw.action_accessible,
        "probe_status": raw.probe_status,
    }
