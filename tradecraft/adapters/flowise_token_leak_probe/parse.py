"""
Pure parsing for flowise_token_leak_probe (CVE-2025-58434).
Extracts vulnerability status, leaked reset token presence, and remediation advice.
No I/O.
"""
from __future__ import annotations

from typing import Any, Dict

from tradecraft.adapters.flowise_token_leak_probe.execute import RawFlowiseResult


def parse_flowise_result(raw: RawFlowiseResult) -> Dict[str, Any]:
    if raw.error and raw.forgot_password_status is None:
        return {
            "target": raw.target,
            "vulnerable": False,
            "status": "error",
            "error": raw.error,
        }

    if raw.token_leaked:
        summary = (
            f"CRITICAL VULNERABILITY: Flowise AI Password Reset Token Leakage (CVE-2025-58434) "
            f"confirmed on {raw.base_url}. The unauthenticated endpoint /api/v1/account/forgot-password "
            f"returned HTTP {raw.forgot_password_status} and leaked the temporary password reset token "
            f"(tempToken preview: {raw.leaked_token_preview}) directly in the JSON response body, "
            f"enabling complete unauthenticated account takeover."
        )
        return {
            "target": raw.target,
            "base_url": raw.base_url,
            "vulnerable": True,
            "cve": "CVE-2025-58434",
            "status": "vulnerable",
            "summary": summary,
            "flowise_detected": raw.flowise_detected,
            "api_accessible": raw.api_accessible,
            "forgot_password_status": raw.forgot_password_status,
            "token_leaked": True,
            "token_preview": raw.leaked_token_preview,
            "evidence_snippet": raw.response_snippet[:300],
            "recommendation": (
                "Upgrade Flowise to version 3.0.5 or later immediately. Ensure Flowise API endpoints "
                "are never exposed directly to the public internet without an authentication reverse proxy."
            ),
        }

    if raw.flowise_detected and raw.api_accessible:
        summary = (
            f"POTENTIALLY EXPOSED: Flowise AI instance detected on {raw.base_url} with active API "
            f"(/api/v1/account/forgot-password returned HTTP {raw.forgot_password_status}), but did not "
            f"leak a reset token for the probed email address."
        )
        return {
            "target": raw.target,
            "base_url": raw.base_url,
            "vulnerable": False,
            "cve": "CVE-2025-58434",
            "status": "partial",
            "summary": summary,
            "flowise_detected": raw.flowise_detected,
            "api_accessible": raw.api_accessible,
            "forgot_password_status": raw.forgot_password_status,
            "evidence_snippet": raw.response_snippet[:300],
            "recommendation": (
                "Verify Flowise version is >= 3.0.5. Restrict access to /api/v1/* to authorized networks only."
            ),
        }

    if not raw.flowise_detected and (raw.forgot_password_status in (404, None)):
        summary = (
            f"NOT_APPLICABLE: Target does not appear to run Flowise AI or forgot-password API returned 404 "
            f"on {raw.base_url}."
        )
        status = "not_applicable"
    else:
        summary = (
            f"SAFE: Flowise forgot-password endpoint was not accessible or rejected unauthenticated token leakage "
            f"(HTTP {raw.forgot_password_status}) on {raw.base_url}."
        )
        status = "safe"

    return {
        "target": raw.target,
        "base_url": raw.base_url,
        "vulnerable": False,
        "cve": "CVE-2025-58434",
        "status": status,
        "summary": summary,
        "flowise_detected": raw.flowise_detected,
        "api_accessible": raw.api_accessible,
        "forgot_password_status": raw.forgot_password_status,
    }
