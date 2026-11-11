"""
Pure parsing for drupal_jsonapi_sqli_probe (CVE-2026-9082).
Extracts vulnerability status, error details, and remediation advice.
No I/O.
"""
from __future__ import annotations

from typing import Any, Dict

from tradecraft.adapters.drupal_jsonapi_sqli_probe.execute import RawDrupalSqliResult


def parse_drupal_sqli_result(raw: RawDrupalSqliResult) -> Dict[str, Any]:
    if raw.error and raw.baseline_status is None:
        return {
            "target": raw.target,
            "vulnerable": False,
            "status": "error",
            "error": raw.error,
        }

    if raw.sqli_confirmed:
        summary = (
            f"CRITICAL VULNERABILITY: Drupal Core JSON:API Error-Based SQL Injection (CVE-2026-9082) "
            f"confirmed on {raw.base_url}{raw.path}. The server reflected injected SQL subquery "
            f"evaluation syntax errors in HTTP 500 error response details without authentication."
        )
        return {
            "target": raw.target,
            "base_url": raw.base_url,
            "path": raw.path,
            "vulnerable": True,
            "cve": "CVE-2026-9082",
            "status": "vulnerable",
            "summary": summary,
            "drupal_detected": raw.drupal_detected,
            "jsonapi_accessible": raw.jsonapi_accessible,
            "baseline_status": raw.baseline_status,
            "probe_status": raw.probe_status,
            "error_detail": raw.probe_error_detail,
            "recommendation": (
                "Update Drupal Core to the latest security release immediately. If using PostgreSQL, "
                "restrict access to JSON:API endpoints (/jsonapi/*) or disable JSON:API filter parameter "
                "exposure to untrusted clients until patched."
            ),
        }

    if not raw.drupal_detected and raw.baseline_status in (404, None):
        summary = (
            f"NOT_APPLICABLE: Target does not appear to run Drupal or JSON:API path {raw.path} "
            f"returned 404 on {raw.base_url}."
        )
        status = "not_applicable"
    else:
        summary = (
            f"SAFE: Target did not trigger SQL syntax injection errors on {raw.base_url}{raw.path} "
            f"(baseline HTTP {raw.baseline_status}, probe HTTP {raw.probe_status})."
        )
        status = "safe"

    return {
        "target": raw.target,
        "base_url": raw.base_url,
        "path": raw.path,
        "vulnerable": False,
        "cve": "CVE-2026-9082",
        "status": status,
        "summary": summary,
        "drupal_detected": raw.drupal_detected,
        "jsonapi_accessible": raw.jsonapi_accessible,
        "baseline_status": raw.baseline_status,
        "probe_status": raw.probe_status,
    }
