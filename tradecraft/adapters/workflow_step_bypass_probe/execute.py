"""
Raw execution for workflow_step_bypass_probe: sends exactly one real
request to a later step of a multi-step process (for example the "payment
confirmed" or "verification complete" endpoint) without first walking the
steps that were supposed to gate it. The caller supplies the request shape
it wants tried; this adapter only classifies the response. A 2xx that
contains the caller-supplied success marker is a confirmed acceptance; a 2xx
without one is reported as unconfirmed. No retries, no method variations.
No parsing here -- that's parse.py's job.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Optional

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tradecraft/1.0"
DEFAULT_TIMEOUT = 10
MAX_BODY_BYTES = 200_000
VALID_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")


@dataclass
class RawWorkflowStepResult:
    target: str = ""
    method: str = "POST"
    status_code: int = 0
    location: str = ""
    body: str = ""
    classification: str = "unknown"
    marker_found: bool = False
    success_marker: str = ""
    error: Optional[str] = None


def normalize_target_url(target: str) -> str:
    value = (target or "").strip()
    if not value:
        return ""
    if not (value.startswith("http://") or value.startswith("https://")):
        value = f"https://{value}"
    return value


def parse_custom_headers(headers_str: Optional[str]) -> dict:
    headers = {"User-Agent": USER_AGENT}
    if headers_str:
        for line in headers_str.splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue
            key, _, value = line.partition(":")
            headers[key.strip()] = value.strip()
    return headers


def _looks_like_json(body: Optional[str]) -> bool:
    if not body:
        return False
    stripped = body.strip()
    if not stripped.startswith(("{", "[")):
        return False
    try:
        json.loads(stripped)
        return True
    except ValueError:
        return False


def execute(
    target: str,
    method: str = "POST",
    body: Optional[str] = None,
    headers: Optional[str] = None,
    success_marker: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> RawWorkflowStepResult:
    result = RawWorkflowStepResult(target=target, method=(method or "POST").upper())
    url = normalize_target_url(target)
    if not url:
        result.error = "empty target URL"
        return result
    if result.method not in VALID_METHODS:
        result.error = f"unsupported method '{method}' (use GET/POST/PUT/PATCH/DELETE)"
        return result
    if requests is None:
        result.error = "requests library not available"
        return result

    req_headers = parse_custom_headers(headers)
    if body:
        req_headers.setdefault(
            "Content-Type",
            "application/json" if _looks_like_json(body) else "application/x-www-form-urlencoded",
        )

    try:
        resp = requests.request(
            result.method,
            url,
            data=body,
            headers=req_headers,
            timeout=timeout,
            verify=False,
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        result.error = str(exc)
        return result

    result.status_code = resp.status_code
    result.location = resp.headers.get("location", "")
    result.body = (resp.text or "")[:MAX_BODY_BYTES]
    result.success_marker = success_marker or ""
    result.marker_found = bool(success_marker and success_marker in result.body)

    if 200 <= resp.status_code < 300:
        result.classification = "accepted_confirmed" if result.marker_found else "accepted_unconfirmed"
    elif resp.status_code in (401, 403):
        result.classification = "blocked"
    elif 300 <= resp.status_code < 400:
        result.classification = "redirected"
    elif 400 <= resp.status_code < 500:
        result.classification = "rejected"
    else:
        result.classification = "server_error"
    return result
