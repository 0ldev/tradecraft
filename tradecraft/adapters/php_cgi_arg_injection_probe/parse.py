"""
Pure parsing for php_cgi_arg_injection_probe (CVE-2024-4577).
Extracts RCE verification status, matched URL, and diagnostic details.
No I/O.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from tradecraft.adapters.php_cgi_arg_injection_probe.execute import PhpCgiProbeAttempt, RawPhpCgiResult


def parse_php_cgi_result(raw: RawPhpCgiResult) -> Dict[str, Any]:
    if raw.error:
        return {
            "target": raw.target,
            "vulnerable": False,
            "status": "error",
            "error": raw.error,
        }

    vulnerable_attempt: Optional[PhpCgiProbeAttempt] = None
    attempts_summary: List[Dict[str, Any]] = []

    for a in raw.attempts:
        entry = {
            "url": a.url,
            "status_code": a.status_code,
            "reflected_token": a.reflected_token,
            "error": a.error,
        }
        attempts_summary.append(entry)
        if a.reflected_token and not vulnerable_attempt:
            vulnerable_attempt = a

    if vulnerable_attempt:
        summary = (
            f"CRITICAL VULNERABILITY: PHP CGI Argument Injection RCE (CVE-2024-4577) confirmed on "
            f"{vulnerable_attempt.url}. The target executed the injected php://input payload and "
            f"reflected the probe execution token."
        )
        return {
            "target": raw.target,
            "base_url": raw.base_url,
            "vulnerable": True,
            "status": "vulnerable",
            "summary": summary,
            "matched_url": vulnerable_attempt.url,
            "probe_token": raw.probe_token,
            "attempts_evaluated": attempts_summary,
            "recommendation": (
                "Upgrade PHP immediately to versions 8.3.8+, 8.2.20+, or 8.1.29+. On Windows Apache "
                "setups, migrate from PHP-CGI to FastCGI/PHP-FPM or disable the Best-Fit encoding mapping."
            ),
        }

    all_404 = all(a.status_code == 404 for a in raw.attempts if a.status_code is not None)
    if all_404 and raw.attempts:
        summary = (
            f"NOT_APPLICABLE: All probed PHP endpoints returned 404 Not Found on {raw.base_url}. "
            f"Target does not appear to expose candidate PHP-CGI scripts."
        )
        status = "not_applicable"
    else:
        summary = (
            f"SAFE: Target did not execute the injected argument payload across "
            f"{len(raw.attempts)} probed endpoint(s)."
        )
        status = "safe"

    return {
        "target": raw.target,
        "base_url": raw.base_url,
        "vulnerable": False,
        "status": status,
        "summary": summary,
        "attempts_evaluated": attempts_summary,
    }
