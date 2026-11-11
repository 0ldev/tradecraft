"""
Pure parsing for ilias_rce_probe (CVE-2026-80428).
Extracts vulnerability status, exposed Shibboleth logout details, and
remediation advice. No I/O.
"""
from __future__ import annotations

from typing import Any, Dict

from tradecraft.adapters.ilias_rce_probe.execute import RawIliasResult


def parse_ilias_result(raw: RawIliasResult) -> Dict[str, Any]:
    if raw.error and raw.ltiauth_status is None and raw.shib_logout_status is None:
        return {
            "target": raw.target,
            "vulnerable": False,
            "status": "error",
            "error": raw.error,
        }

    # Both LTI entry point and Shibboleth SOAP handler responsive -> Vulnerable
    if raw.shib_logout_responsive and raw.ltiauth_accessible:
        summary = (
            f"CRITICAL VULNERABILITY: ILIAS unauthenticated PHP Object Injection (CVE-2026-80428) "
            f"confirmed on {raw.base_url}. Both /ltiauth.php (session parameter seeding) and "
            f"/shib_logout.php (SOAP LogoutNotification unserialize handler) are exposed and active."
        )
        return {
            "target": raw.target,
            "base_url": raw.base_url,
            "vulnerable": True,
            "cve": "CVE-2026-80428",
            "status": "vulnerable",
            "summary": summary,
            "ltiauth_accessible": raw.ltiauth_accessible,
            "ltiauth_status": raw.ltiauth_status,
            "shib_logout_responsive": raw.shib_logout_responsive,
            "shib_logout_status": raw.shib_logout_status,
            "evidence_snippet": raw.shib_response_snippet[:300],
            "ilias_fingerprinted": raw.ilias_fingerprinted,
            "recommendation": (
                "Upgrade ILIAS immediately to version 9.22, 10.10, 11.3 or higher. If upgrading "
                "is delayed, block external access to /shib_logout.php and /ltiauth.php on the web server."
            ),
        }

    # If shib_logout responds but ltiauth is not accessible, still dangerous
    if raw.shib_logout_responsive:
        summary = (
            f"POTENTIALLY VULNERABLE: Shibboleth SOAP logout handler (/shib_logout.php) responded on "
            f"{raw.base_url}, but /ltiauth.php returned status {raw.ltiauth_status}."
        )
        return {
            "target": raw.target,
            "base_url": raw.base_url,
            "vulnerable": False,
            "cve": "CVE-2026-80428",
            "status": "partial",
            "summary": summary,
            "ltiauth_accessible": raw.ltiauth_accessible,
            "shib_logout_responsive": raw.shib_logout_responsive,
            "evidence_snippet": raw.shib_response_snippet[:300],
            "ilias_fingerprinted": raw.ilias_fingerprinted,
        }

    if not raw.ilias_fingerprinted and (raw.ltiauth_status in (404, None) and raw.shib_logout_status in (404, None)):
        summary = (
            f"NOT_APPLICABLE: Target does not appear to run ILIAS e-Learning or endpoints returned 404 on {raw.base_url}."
        )
        status = "not_applicable"
    else:
        summary = (
            f"SAFE: Target did not exhibit unauthenticated Shibboleth SOAP logout handler response on {raw.base_url}."
        )
        status = "safe"

    return {
        "target": raw.target,
        "base_url": raw.base_url,
        "vulnerable": False,
        "cve": "CVE-2026-80428",
        "status": status,
        "summary": summary,
        "ltiauth_accessible": raw.ltiauth_accessible,
        "shib_logout_responsive": raw.shib_logout_responsive,
        "ilias_fingerprinted": raw.ilias_fingerprinted,
    }
