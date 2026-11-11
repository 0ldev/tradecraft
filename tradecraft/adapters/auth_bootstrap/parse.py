"""
Pure parsing and credential generation helpers for auth_bootstrap. No I/O here.
"""
from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional, Tuple


def normalize_target_url(target: str) -> str:
    """Normalize target to full URL defaulting to https://."""
    target = target.strip()
    if target.startswith("http://") or target.startswith("https://"):
        return target
    return f"https://{target}"


def generate_account_credentials(suffix: Optional[str] = None) -> Tuple[str, str]:
    """Generates disposable email and high-entropy password."""
    s = suffix or uuid.uuid4().hex[:10]
    email = f"tradecraft_probe_{s}@example.com"
    password = f"Tradecraft!{s}#1A"
    return email, password


def build_registration_payloads(email: str, password: str) -> List[Dict[str, str]]:
    """Builds common registration JSON/form payload structures."""
    return [
        {"email": email, "password": password},
        {"username": email, "password": password},
        {"email": email, "password": password, "passwordRepeat": password},
        {"username": email, "password": password, "passwordConfirm": password},
    ]


def extract_session_token(
    data: Optional[Dict[str, Any]],
    headers: Dict[str, str],
    cookies: Dict[str, str],
) -> Optional[str]:
    """Extracts session token or session cookie from response JSON, headers, or cookies."""
    # 1. Inspect JSON payload
    if isinstance(data, dict):
        # Nested auth dict e.g. JuiceShop / standard APIs
        auth_nested = data.get("authentication")
        if isinstance(auth_nested, dict):
            tok = auth_nested.get("token") or auth_nested.get("jwt")
            if tok:
                return str(tok)

        for key in (
            "token",
            "access_token",
            "jwt",
            "id_token",
            "session_token",
            "sessionId",
            "key",
            "apiKey",
        ):
            val = data.get(key)
            if val and isinstance(val, (str, int)):
                return str(val)

    auth_header = headers.get("Authorization") or headers.get("authorization") or ""
    if "Bearer " in auth_header:
        parts = auth_header.split("Bearer ", 1)
        if len(parts) > 1 and parts[1].strip():
            return parts[1].strip()

    # 3. Inspect cookies
    cookie_markers = ("token", "jwt", "session", "auth", "sid", "phpsessid", "connect.sid")
    for cookie_name, cookie_val in cookies.items():
        c_lower = cookie_name.lower()
        if any(marker in c_lower for marker in cookie_markers):
            return f"{cookie_name}={cookie_val}"

    return None
