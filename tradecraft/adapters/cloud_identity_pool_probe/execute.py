"""
Execution logic for cloud_identity_pool_probe: checks whether an AWS
Cognito Identity Pool grants unauthenticated identities real temporary
AWS credentials. Uses AWS's plain JSON 1.1 protocol directly over
requests -- no boto3/AWS SDK dependency, same no-new-third-party-
dependency rule the rest of this project's adapters follow. No parsing
here -- that's parse.py's job.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tradecraft/1.0"
MAX_POOL_IDS = 5


@dataclass
class IdentityPoolAttempt:
    identity_pool_id: str
    region: str = ""
    get_id_status: Optional[int] = None
    identity_id: str = ""
    get_id_error: str = ""
    get_credentials_status: Optional[int] = None
    access_key_id: str = ""
    secret_key: str = ""
    session_token: str = ""
    credentials_obtained: bool = False
    vulnerable: bool = False
    status: str = "unknown"  # "vulnerable", "identity_creation_denied", "credentials_denied", "error", "unexpected_response"
    error: Optional[str] = None


@dataclass
class CloudIdentityPoolResult:
    target: str = ""
    attempts: List[IdentityPoolAttempt] = field(default_factory=list)
    vulnerable: bool = False
    summary: str = ""
    error: Optional[str] = None


def _infer_region(identity_pool_id: str) -> str:
    """Identity Pool ids are formatted '<region>:<uuid>', e.g.
    'us-east-1:1a2b3c4d-...'."""
    if ":" in identity_pool_id:
        return identity_pool_id.split(":", 1)[0].strip()
    return ""


def _aws_json_post(region: str, action: str, body: Dict, timeout: float):
    url = f"https://cognito-identity.{region}.amazonaws.com/"
    headers = {
        "Content-Type": "application/x-amz-json-1.1",
        "X-Amz-Target": f"AWSCognitoIdentityService.{action}",
        "User-Agent": USER_AGENT,
    }
    return requests.post(url, json=body, headers=headers, timeout=timeout, verify=False)


def probe_identity_pool(identity_pool_id: str, region: Optional[str] = None, timeout: float = 10.0) -> IdentityPoolAttempt:
    pool_id = identity_pool_id.strip()
    effective_region = (region or _infer_region(pool_id)).strip()
    res = IdentityPoolAttempt(identity_pool_id=pool_id, region=effective_region)

    if not effective_region:
        res.status = "error"
        res.error = f"could not infer region from '{pool_id}' (expected '<region>:<uuid>') and none was given"
        return res
    if requests is None:
        res.status = "error"
        res.error = "requests library not available"
        return res

    # Step 1 (weaker signal): unauthenticated identity creation allowed
    # at all. Many pools allow this but still gate real credentials
    # behind IAM trust conditions, so this alone is not the finding.
    try:
        get_id_resp = _aws_json_post(effective_region, "GetId", {"IdentityPoolId": pool_id}, timeout)
    except requests.RequestException as exc:
        res.status = "error"
        res.error = str(exc)
        return res

    res.get_id_status = get_id_resp.status_code
    try:
        get_id_data = get_id_resp.json()
    except ValueError:
        res.status = "unexpected_response"
        return res

    if get_id_resp.status_code != 200 or "IdentityId" not in get_id_data:
        res.status = "identity_creation_denied"
        res.get_id_error = str(get_id_data.get("message", ""))
        return res
    res.identity_id = get_id_data["IdentityId"]

    # Step 2 (strong signal): a real, usable set of temporary AWS
    # credentials handed to an anonymous visitor with no login at all.
    try:
        creds_resp = _aws_json_post(
            effective_region, "GetCredentialsForIdentity", {"IdentityId": res.identity_id}, timeout,
        )
    except requests.RequestException as exc:
        res.status = "error"
        res.error = str(exc)
        return res

    res.get_credentials_status = creds_resp.status_code
    try:
        creds_data = creds_resp.json()
    except ValueError:
        res.status = "unexpected_response"
        return res

    if creds_resp.status_code != 200 or "Credentials" not in creds_data:
        res.status = "credentials_denied"
        return res

    credentials = creds_data["Credentials"]
    res.access_key_id = credentials.get("AccessKeyId", "")
    res.secret_key = credentials.get("SecretKey", "")
    res.session_token = credentials.get("SessionToken", "")
    res.credentials_obtained = bool(res.access_key_id and res.secret_key)
    if res.credentials_obtained:
        res.vulnerable = True
        res.status = "vulnerable"
    else:
        res.status = "unexpected_response"
    return res


def execute(identity_pool_id: str, region: Optional[str] = None, timeout: int = 10) -> CloudIdentityPoolResult:
    pool_ids = [p.strip() for p in (identity_pool_id or "").split(",") if p.strip()][:MAX_POOL_IDS]
    if not pool_ids:
        return CloudIdentityPoolResult(target=identity_pool_id, error="no identity_pool_id provided")

    effective_timeout = max(1.0, min(float(timeout), 20.0))
    attempts = [probe_identity_pool(pid, region=region, timeout=effective_timeout) for pid in pool_ids]

    is_vuln = any(a.vulnerable for a in attempts)
    summary_parts = []
    for a in attempts:
        if a.vulnerable:
            summary_parts.append(f"{a.identity_pool_id} VULNERABLE: unauthenticated AWS credentials obtained")
        else:
            summary_parts.append(f"{a.identity_pool_id}: {a.status}")

    return CloudIdentityPoolResult(
        target=identity_pool_id,
        attempts=attempts,
        vulnerable=is_vuln,
        summary="; ".join(summary_parts),
    )
