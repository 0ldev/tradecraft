"""
Execution logic for auth_bootstrap: attempts self-registration and login
using disposable throwaway credentials. No parsing here -- see parse.py.
"""
from __future__ import annotations

import urllib.parse
from dataclasses import dataclass
from typing import Optional, Tuple

import requests
import urllib3

from tradecraft.adapters.auth_bootstrap import parse as auth_parse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_REGISTER_PATHS = (
    "/register",
    "/api/Users/",
    "/api/Users",
    "/api/register",
    "/signup",
    "/api/signup",
    "/user/register",
    "/auth/register",
)

DEFAULT_LOGIN_PATHS = (
    "/login",
    "/rest/user/login",
    "/api/login",
    "/api/Users/login",
    "/auth/login",
    "/user/login",
)


@dataclass
class RawAuthBootstrapResult:
    registered: bool = False
    session_token: Optional[str] = None
    email_used: str = ""
    registration_endpoint: Optional[str] = None
    login_endpoint: Optional[str] = None
    error: Optional[str] = None


def _extract_token_safely(resp: "requests.Response") -> Optional[str]:
    """Best-effort session-token extraction straight from a response that
    already looked like a success (status 200/201) -- never raises, so a
    response shaped unlike what extract_session_token expects just means
    no token found this way, not a crashed probe."""
    try:
        try:
            data = resp.json()
        except Exception:
            data = None
        return auth_parse.extract_session_token(
            data=data if isinstance(data, dict) else None,
            headers=dict(resp.headers) if resp.headers else {},
            cookies=resp.cookies.get_dict() if hasattr(resp.cookies, "get_dict") else {},
        )
    except Exception:
        return None


def _try_register(
    session: requests.Session,
    base_url: str,
    email: str,
    password: str,
    paths: Tuple[str, ...],
    timeout: int = 10,
) -> Tuple[bool, Optional[str], Optional[str]]:
    """Returns (registered, registration_endpoint, session_token). The
    third value is only set when the registration response itself
    already carries a usable session/token -- some real APIs (e.g.
    Supabase's /auth/v1/signup) issue a session directly on signup with
    no separate login step at all."""
    payloads = auth_parse.build_registration_payloads(email, password)

    for path in paths:
        url = urllib.parse.urljoin(base_url, path)
        for payload in payloads:
            for use_json in (True, False):
                kwargs = {"json": payload} if use_json else {"data": payload}
                try:
                    resp = session.post(
                        url,
                        timeout=timeout,
                        allow_redirects=False,
                        verify=False,
                        **kwargs,
                    )
                except requests.RequestException:
                    continue

                if resp.status_code in (200, 201):
                    return True, url, _extract_token_safely(resp)

    return False, None, None


def _try_login(
    session: requests.Session,
    base_url: str,
    email: str,
    password: str,
    paths: Tuple[str, ...],
    timeout: int = 10,
) -> Tuple[Optional[str], Optional[str]]:
    login_payloads = [
        {"email": email, "password": password},
        {"username": email, "password": password},
    ]

    for path in paths:
        url = urllib.parse.urljoin(base_url, path)
        for payload in login_payloads:
            for use_json in (True, False):
                try:
                    kwargs = {"json": payload} if use_json else {"data": payload}
                    resp = session.post(
                        url,
                        timeout=timeout,
                        allow_redirects=False,
                        verify=False,
                        **kwargs,
                    )
                except requests.RequestException:
                    continue

                if resp.status_code not in (200, 201, 302):
                    continue

                try:
                    data = resp.json()
                except Exception:
                    data = None

                token = auth_parse.extract_session_token(
                    data=data,
                    headers=dict(resp.headers),
                    cookies=resp.cookies.get_dict(),
                )
                if token:
                    return token, url

    return None, None


def execute(
    target: str,
    register_path: str = "",
    login_path: str = "",
    timeout: int = 10,
) -> RawAuthBootstrapResult:
    target = target.strip()
    if not target:
        return RawAuthBootstrapResult(error="Target cannot be empty")

    base_url = auth_parse.normalize_target_url(target)
    if not base_url.endswith("/"):
        base_url += "/"

    email, password = auth_parse.generate_account_credentials()

    reg_paths = (register_path,) if register_path.strip() else DEFAULT_REGISTER_PATHS
    login_paths = (login_path,) if login_path.strip() else DEFAULT_LOGIN_PATHS

    session = requests.Session()

    # Attempt registration
    registered, reg_endpoint, token_from_registration = _try_register(
        session=session,
        base_url=base_url,
        email=email,
        password=password,
        paths=reg_paths,
        timeout=timeout,
    )

    if token_from_registration:
        # The registration response itself already carried a usable
        # session -- no separate login call needed or attempted.
        return RawAuthBootstrapResult(
            registered=True,
            session_token=token_from_registration,
            email_used=email,
            registration_endpoint=reg_endpoint,
            login_endpoint=None,
            error=None,
        )

    # Attempt login
    session_token, login_endpoint = _try_login(
        session=session,
        base_url=base_url,
        email=email,
        password=password,
        paths=login_paths,
        timeout=timeout,
    )

    if not registered and not session_token:
        return RawAuthBootstrapResult(
            registered=False,
            session_token=None,
            email_used=email,
            error=f"Registration and login failed across probed endpoints on {base_url}",
        )

    return RawAuthBootstrapResult(
        registered=registered,
        session_token=session_token,
        email_used=email,
        registration_endpoint=reg_endpoint,
        login_endpoint=login_endpoint,
        error=None if session_token else "Registration succeeded but login failed to return session token",
    )
