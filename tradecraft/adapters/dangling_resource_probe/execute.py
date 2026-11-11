"""
Raw execution for dangling_resource_probe: one anonymous GET to a
candidate dangling hostname, checked against a small built-in table of
well-known "this cloud resource is unclaimed" response signatures. No
external binary required (unlike subzy, which wraps a separate Go tool) --
a pure-Python complement, not a replacement. No parsing here -- parse.py.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Tuple

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tradecraft/1.0"

# (provider_label, signature_substring) -- a small, well-documented subset,
# not a comprehensive database (subzy's own larger fingerprint DB is the
# broader-coverage tool; this is a no-binary-required complement).
FINGERPRINTS: List[Tuple[str, str]] = [
    ("github_pages", "There isn't a GitHub Pages site here."),
    ("heroku", "No such app"),
    ("azure_web_app", "404 Web Site not found"),
    ("aws_s3_website", "The specified bucket does not exist"),
    ("fastly", "Fastly error: unknown domain"),
    ("shopify", "Sorry, this shop is currently unavailable"),
]


@dataclass
class RawDanglingResult:
    target: str = ""
    host: str = ""
    status_code: int = 0
    matched_provider: Optional[str] = None
    matched_signature: Optional[str] = None
    body_snippet: str = ""
    error: Optional[str] = None


def normalize_host_url(target: str) -> Tuple[str, str]:
    cleaned = (target or "").strip()
    if not cleaned:
        return "", ""
    url = cleaned if cleaned.startswith(("http://", "https://")) else f"https://{cleaned}"
    host = cleaned.split("://", 1)[-1].split("/", 1)[0]
    return url, host


def execute(target: str, timeout: int = 10) -> RawDanglingResult:
    url, host = normalize_host_url(target)
    result = RawDanglingResult(target=target, host=host)
    if not url:
        result.error = "empty target provided"
        return result
    if requests is None:
        result.error = "requests library not available"
        return result

    try:
        resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=timeout, verify=False)
    except requests.RequestException as exc:
        result.error = f"request failed: {exc}"
        return result

    result.status_code = resp.status_code
    body = resp.text or ""
    result.body_snippet = body[:2000]

    for provider, signature in FINGERPRINTS:
        if signature in body:
            result.matched_provider = provider
            result.matched_signature = signature
            break

    return result
