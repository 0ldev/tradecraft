"""
Raw execution for bucket_permission_probe: one unauthenticated GET per check
against each provider's public REST API. No credentials are used or sent.
Read-only -- no object is ever written. No parsing here -- that's parse.py's job.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import List, Optional

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tradecraft/1.0"

PROVIDERS = ("aws", "gcp", "azure")

DEFAULT_AZURE_CONTAINERS = [
    "data", "backup", "files", "public", "container", "media",
    "uploads", "docs", "images", "$root",
]
MAX_AZURE_CONTAINERS = 10
# Upper bound on candidate-account x container pairs in one Azure call.
MAX_AZURE_PAIRS = 50


@dataclass
class BucketCheck:
    candidate: str
    container: Optional[str] = None  # azure only
    exists: Optional[bool] = None
    publicly_listable: Optional[bool] = None
    status: Optional[int] = None
    error: Optional[str] = None


@dataclass
class RawBucketPermissionResult:
    provider: str = ""
    checks: List[BucketCheck] = field(default_factory=list)
    truncated: bool = False
    error: Optional[str] = None


def normalize_bucket_candidate(provider: str, raw: str) -> str:
    """Strips a known provider suffix if present, else returns raw
    unchanged (already a bare name)."""
    raw = raw.strip()
    if provider == "aws":
        for suffix in (".s3.amazonaws.com",):
            if raw.endswith(suffix):
                return raw[: -len(suffix)]
        # regional form: <bucket>.s3.<region>.amazonaws.com
        m = re.match(r"^(.+)\.s3[.-][\w-]+\.amazonaws\.com$", raw)
        if m:
            return m.group(1)
    elif provider == "gcp":
        if raw.endswith(".storage.googleapis.com"):
            return raw[: -len(".storage.googleapis.com")]
    elif provider == "azure":
        if raw.endswith(".blob.core.windows.net"):
            return raw[: -len(".blob.core.windows.net")]
    return raw


def _get(url: str, timeout: int):
    return requests.get(
        url,
        timeout=timeout,
        verify=False,
        headers={"User-Agent": USER_AGENT},
    )


def _check_aws(candidate: str, timeout: int) -> BucketCheck:
    check = BucketCheck(candidate=candidate)
    url = f"https://{candidate}.s3.amazonaws.com/?list-type=2&max-keys=5"
    try:
        resp = _get(url, timeout)
    except requests.RequestException as exc:
        check.error = str(exc)
        return check
    check.status = resp.status_code
    if resp.status_code == 200:
        if "<ListBucketResult" in resp.text:
            check.exists, check.publicly_listable = True, True
        else:
            check.error = "HTTP 200 without a ListBucketResult body"
    elif resp.status_code == 403:
        # Existing but private: AWS answers AccessDenied.
        check.exists, check.publicly_listable = True, False
    elif resp.status_code == 404:
        check.exists, check.publicly_listable = False, False
    else:
        check.error = f"unexpected HTTP {resp.status_code}"
    return check


def _check_gcp(candidate: str, timeout: int) -> BucketCheck:
    check = BucketCheck(candidate=candidate)
    url = f"https://storage.googleapis.com/storage/v1/b/{candidate}/o?maxResults=5"
    try:
        resp = _get(url, timeout)
    except requests.RequestException as exc:
        check.error = str(exc)
        return check
    check.status = resp.status_code
    if resp.status_code == 200:
        try:
            json.loads(resp.text)
        except ValueError:
            check.error = "HTTP 200 with a non-JSON body"
        else:
            check.exists, check.publicly_listable = True, True
    elif resp.status_code == 403:
        check.exists, check.publicly_listable = True, False
    elif resp.status_code == 404:
        check.exists, check.publicly_listable = False, False
    else:
        check.error = f"unexpected HTTP {resp.status_code}"
    return check


def _check_azure(candidate: str, container: str, timeout: int) -> BucketCheck:
    check = BucketCheck(candidate=candidate, container=container)
    url = (
        f"https://{candidate}.blob.core.windows.net/{container}"
        "?restype=container&comp=list&maxresults=5"
    )
    try:
        resp = _get(url, timeout)
    except requests.RequestException as exc:
        check.error = str(exc)
        return check
    check.status = resp.status_code
    if resp.status_code == 200:
        if "<EnumerationResults" in resp.text:
            # exists/publicly_listable here describe this container only.
            check.exists, check.publicly_listable = True, True
        else:
            check.error = "HTTP 200 without an EnumerationResults body"
    elif resp.status_code == 403:
        check.exists, check.publicly_listable = True, False
    elif resp.status_code == 404 and "ContainerNotFound" in resp.text:
        # One container miss says nothing about the account itself.
        check.exists, check.publicly_listable = False, False
    else:
        check.error = f"unexpected HTTP {resp.status_code}"
    return check


def execute(
    provider: str,
    buckets: str,
    azure_containers: str = "",
    timeout: int = 10,
) -> RawBucketPermissionResult:
    provider = (provider or "").strip().lower()
    if provider not in PROVIDERS:
        return RawBucketPermissionResult(
            provider=provider,
            error=f"unsupported provider '{provider}': expected aws, gcp, or azure",
        )
    if requests is None:
        return RawBucketPermissionResult(provider=provider, error="requests library not available")

    candidates = [
        normalize_bucket_candidate(provider, b)
        for b in (buckets or "").split(",")
        if b.strip()
    ]
    candidates = [c for c in candidates if c]
    if not candidates:
        return RawBucketPermissionResult(provider=provider, error="no bucket candidates given")

    raw = RawBucketPermissionResult(provider=provider)

    if provider == "aws":
        raw.checks = [_check_aws(c, timeout) for c in candidates]
    elif provider == "gcp":
        raw.checks = [_check_gcp(c, timeout) for c in candidates]
    else:
        containers = (
            [c.strip() for c in azure_containers.split(",") if c.strip()]
            if azure_containers
            else []
        )
        if not containers:
            containers = list(DEFAULT_AZURE_CONTAINERS)
        containers = containers[:MAX_AZURE_CONTAINERS]

        max_accounts = MAX_AZURE_PAIRS // len(containers)
        if len(candidates) > max_accounts:
            candidates = candidates[:max_accounts]
            raw.truncated = True

        for candidate in candidates:
            for container in containers:
                raw.checks.append(_check_azure(candidate, container, timeout))

    return raw
