"""
Raw execution for ilias_rce_probe (CVE-2026-80428).
Probes ILIAS e-Learning platforms for unauthenticated PHP Object Injection
via the Shibboleth back-channel logout endpoint (/shib_logout.php) and LTI
entry point (/ltiauth.php).
No parsing here -- parse.py's job.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tradecraft/1.0"

SOAP_LOGOUT_PROBE = (
    b'<?xml version="1.0" encoding="UTF-8"?>\n'
    b'<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" '
    b'xmlns:ns1="urn:mace:shibboleth:2.0:sp:notify">\n'
    b'<SOAP-ENV:Body>\n'
    b'  <ns1:LogoutNotification>\n'
    b'    <SessionID>tradecraft_cve_2026_80428_probe</SessionID>\n'
    b'  </ns1:LogoutNotification>\n'
    b'</SOAP-ENV:Body>\n'
    b'</SOAP-ENV:Envelope>'
)


@dataclass
class RawIliasResult:
    target: str = ""
    base_url: str = ""
    ltiauth_status: Optional[int] = None
    ltiauth_accessible: bool = False
    shib_logout_status: Optional[int] = None
    shib_logout_responsive: bool = False
    shib_response_snippet: str = ""
    ilias_fingerprinted: bool = False
    error: Optional[str] = None


def normalize_target_url(target: str) -> str:
    t = target.strip()
    if not t.startswith("http://") and not t.startswith("https://"):
        t = f"https://{t}"
    return t.rstrip("/")


def execute(
    target: str,
    host_header: Optional[str] = None,
    timeout: int = 8,
) -> RawIliasResult:
    if requests is None:
        return RawIliasResult(target=target, error="requests library not available")

    if not target or not target.strip():
        return RawIliasResult(target="", error="target is required")

    base_url = normalize_target_url(target)
    result = RawIliasResult(target=target.strip(), base_url=base_url)

    session = requests.Session()
    headers = {"User-Agent": USER_AGENT}
    if host_header and host_header.strip():
        headers["Host"] = host_header.strip()

    session.headers.update(headers)

    # Step 1: Fingerprint ILIAS and probe /ltiauth.php
    try:
        r_home = session.get(f"{base_url}/", timeout=timeout, verify=False, allow_redirects=True)
        home_text = r_home.text.lower()
        if "ilias" in home_text or "ilias" in str(r_home.headers).lower():
            result.ilias_fingerprinted = True
    except requests.exceptions.RequestException:
        pass

    try:
        # Test LTI entry point
        r_lti = session.post(
            f"{base_url}/ltiauth.php",
            data="lti_message_hint=1%3A2",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=timeout,
            verify=False,
            allow_redirects=False,
        )
        result.ltiauth_status = r_lti.status_code
        if r_lti.status_code in (200, 302, 400):
            result.ltiauth_accessible = True
    except requests.exceptions.RequestException as e:
        if not result.error:
            result.error = f"ltiauth probe failed: {e}"

    # Step 2: Probe Shibboleth back-channel logout endpoint with SOAP probe
    try:
        r_shib = session.post(
            f"{base_url}/shib_logout.php",
            data=SOAP_LOGOUT_PROBE,
            headers={"Content-Type": "text/xml"},
            timeout=timeout,
            verify=False,
            allow_redirects=False,
        )
        result.shib_logout_status = r_shib.status_code
        shib_text = r_shib.text or ""
        result.shib_response_snippet = shib_text[:500]

        if r_shib.status_code == 200 and (
            "LogoutNotificationResponse" in shib_text
            or "<OK/>" in shib_text
            or "soap" in shib_text.lower()
        ):
            result.shib_logout_responsive = True

    except requests.exceptions.RequestException as e:
        if not result.error:
            result.error = f"shib_logout probe failed: {e}"

    return result
