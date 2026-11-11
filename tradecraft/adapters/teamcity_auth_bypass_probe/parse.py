"""
Pure parsing for teamcity_auth_bypass_probe (CVE-2024-27198 & CVE-2024-27199).
Extracts auth bypass status, server version info, and diagnostic telemetry.
No I/O.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from tradecraft.adapters.teamcity_auth_bypass_probe.execute import RawTeamCityResult, TeamCityProbeAttempt


def parse_teamcity_result(raw: RawTeamCityResult) -> Dict[str, Any]:
    if raw.error:
        return {
            "target": raw.target,
            "vulnerable": False,
            "status": "error",
            "error": raw.error,
        }

    vulnerable_attempt: Optional[TeamCityProbeAttempt] = None
    attempts_summary: List[Dict[str, Any]] = []

    for a in raw.attempts:
        entry = {
            "url": a.url,
            "status_code": a.status_code,
            "is_vulnerable": a.is_vulnerable,
            "error": a.error,
        }
        attempts_summary.append(entry)
        if a.is_vulnerable and not vulnerable_attempt:
            vulnerable_attempt = a

    if vulnerable_attempt:
        version_str = vulnerable_attempt.server_info.get("version") or "unknown"
        build_str = vulnerable_attempt.server_info.get("buildNumber") or ""
        ver_display = f" {version_str} (build {build_str})" if build_str else f" {version_str}"

        summary = (
            f"CRITICAL VULNERABILITY: JetBrains TeamCity Authentication Bypass "
            f"(CVE-2024-27198 / CVE-2024-27199) confirmed on {vulnerable_attempt.url}. "
            f"Unauthenticated access granted to internal REST API endpoints{ver_display}."
        )
        return {
            "target": raw.target,
            "base_url": raw.base_url,
            "vulnerable": True,
            "status": "vulnerable",
            "summary": summary,
            "matched_url": vulnerable_attempt.url,
            "server_info": vulnerable_attempt.server_info,
            "teamcity_fingerprinted": raw.teamcity_fingerprinted,
            "attempts_evaluated": attempts_summary,
            "recommendation": (
                "Immediately update JetBrains TeamCity to version 2023.11.4 or higher, or install the "
                "official JetBrains security patch plugin. Restrict access to TeamCity management ports."
            ),
        }

    if not raw.teamcity_fingerprinted and all(
        a.status_code in (404, None) for a in raw.attempts
    ):
        summary = (
            f"NOT_APPLICABLE: Target does not appear to expose a JetBrains TeamCity instance on {raw.base_url}."
        )
        status = "not_applicable"
    else:
        summary = (
            f"SAFE: Target did not grant unauthenticated access across {len(raw.attempts)} probed bypass endpoint(s)."
        )
        status = "safe"

    return {
        "target": raw.target,
        "base_url": raw.base_url,
        "vulnerable": False,
        "status": status,
        "summary": summary,
        "teamcity_fingerprinted": raw.teamcity_fingerprinted,
        "attempts_evaluated": attempts_summary,
    }
