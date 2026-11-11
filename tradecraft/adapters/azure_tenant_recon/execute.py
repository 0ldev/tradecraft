"""
Raw execution for azure_tenant_recon: one OIDC well-known GET for tenant
discovery, then up to MAX_USERNAMES unauthenticated POSTs to Azure AD's
GetCredentialType endpoint. No sign-in is attempted and no password is sent.
No parsing here -- that's parse.py's job.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tradecraft/1.0"

# Hard cap on usernames checked per call (extra entries are dropped, not an error).
MAX_USERNAMES = 25

_TENANT_RE = re.compile(r"/([0-9a-f-]{36})/")


@dataclass
class UsernameCheck:
    username: str
    exists: Optional[bool] = None
    if_exists_result: Optional[int] = None  # raw IfExistsResult, kept for every code
    throttle_status: Optional[int] = None  # IfExistsResult -1 is treated as throttled
    namespace_type: Optional[str] = None  # GetCredentialType's NameSpaceType (Managed/Federated/...)
    error: Optional[str] = None


@dataclass
class RawAzureTenantResult:
    domain: str = ""
    is_azure_ad: bool = False
    tenant_id: Optional[str] = None
    domain_namespace_type: Optional[str] = None  # Managed / Federated, from a domain-level lookup
    checks: List[UsernameCheck] = field(default_factory=list)
    error: Optional[str] = None


def _discover_tenant(domain: str, timeout: int, raw: RawAzureTenantResult) -> None:
    """Sets raw.is_azure_ad / raw.tenant_id from the OIDC well-known document.
    A non-200 response is a completed 'not Azure AD' outcome. A request that
    raised is a genuine network error and goes to raw.error."""
    url = f"https://login.microsoftonline.com/{domain}/.well-known/openid-configuration"
    try:
        resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=timeout, verify=False)
    except requests.RequestException as exc:
        raw.error = str(exc)
        return
    if resp.status_code != 200:
        raw.is_azure_ad = False
        return
    raw.is_azure_ad = True
    try:
        issuer = json.loads(resp.text).get("issuer", "")
    except (ValueError, AttributeError):
        issuer = ""
    m = _TENANT_RE.search(issuer or "")
    raw.tenant_id = m.group(1) if m else None


def _check_username(username: str, timeout: int) -> UsernameCheck:
    check = UsernameCheck(username=username)
    url = "https://login.microsoftonline.com/common/GetCredentialType"
    try:
        resp = requests.post(
            url,
            data=json.dumps({"Username": username}),
            headers={
                "Content-Type": "application/json; charset=UTF-8",
                "User-Agent": USER_AGENT,
            },
            timeout=timeout,
            verify=False,
        )
    except requests.RequestException as exc:
        check.error = str(exc)
        return check
    try:
        body = json.loads(resp.text)
    except ValueError:
        check.error = f"HTTP {resp.status_code} with a non-JSON body"
        return check

    check.namespace_type = body.get("NameSpaceType")
    result = body.get("IfExistsResult")
    check.if_exists_result = result if isinstance(result, int) else None
    # Only 0 (exists) and 1 (does not exist) are mapped to a definite answer.
    # Public references do not define 5, 6, or -1 for IfExistsResult, so those
    # stay unresolved (exists=None) instead of being guessed as found or
    # missing. -1 is still flagged as throttled, which is the only meaning the
    # tool gives it.
    if result == 0:
        check.exists = True
    elif result == 1:
        check.exists = False
    elif result == -1:
        check.exists = None
        check.throttle_status = -1
    elif result in (5, 6):
        check.exists = None
    else:
        check.error = f"unrecognized IfExistsResult {result!r}"
    return check


def _domain_namespace(domain: str, timeout: int) -> Optional[str]:
    """Managed/Federated status of the domain itself. GetCredentialType
    returns NameSpaceType for any username on the domain, so one lookup on a
    fixed, deliberately non-existent local part reports it without touching a
    real account. Returns None if the lookup fails."""
    check = _check_username(f"tradecraft-namespace-probe@{domain}", timeout)
    return check.namespace_type if check.error is None else None


def _dedupe_usernames(usernames: str) -> List[str]:
    seen: Dict[str, None] = {}
    for u in usernames.split(","):
        u = u.strip()
        if u:
            seen.setdefault(u, None)
    return list(seen)[:MAX_USERNAMES]


def execute(domain: str, usernames: str = "", timeout: int = 10) -> RawAzureTenantResult:
    domain = (domain or "").strip().lower()
    raw = RawAzureTenantResult(domain=domain)
    if not domain:
        raw.error = "no domain given"
        return raw
    if requests is None:
        raw.error = "requests library not available"
        return raw

    _discover_tenant(domain, timeout, raw)
    if raw.error or not raw.is_azure_ad:
        return raw
    raw.domain_namespace_type = _domain_namespace(domain, timeout)
    if not usernames:
        return raw

    for username in _dedupe_usernames(usernames):
        raw.checks.append(_check_username(username, timeout))
    return raw
