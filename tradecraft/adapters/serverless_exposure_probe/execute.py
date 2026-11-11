"""
Execution logic for serverless_exposure_probe: GETs candidate serverless
function endpoints (AWS Lambda Function URLs, Azure Function Apps, GCP
Cloud Functions) unauthenticated, across providers. No parsing here --
that's parse.py's job.
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

DEFAULT_TIMEOUT = 10
MAX_BODY_BYTES = 200_000
DEFAULT_FUNCTION_NAMES = ("default", "api", "health")
MAX_URLS = 20


@dataclass
class RawFunctionCheck:
    url: str
    status_code: int = 0
    body: str = ""
    error: Optional[str] = None


@dataclass
class RawServerlessExposureResult:
    provider: str = ""
    checks: List[RawFunctionCheck] = field(default_factory=list)
    error: Optional[str] = None


def _candidate_urls(provider: str, candidates: str, function_names: Optional[str]) -> List[str]:
    provider = provider.lower()
    raw_candidates = [c.strip() for c in candidates.split(",") if c.strip()]
    names = [n.strip() for n in (function_names or ",".join(DEFAULT_FUNCTION_NAMES)).split(",") if n.strip()]

    urls: List[str] = []
    for cand in raw_candidates:
        if cand.startswith("http://") or cand.startswith("https://"):
            urls.append(cand)
            continue

        if provider == "aws":
            # cand is a Lambda Function URL id; the region may be embedded as
            # "id:region" or default to us-east-1.
            if ":" in cand:
                fn_id, region = cand.split(":", 1)
            else:
                fn_id, region = cand, "us-east-1"
            urls.append(f"https://{fn_id}.lambda-url.{region}.on.aws/")
        elif provider == "azure":
            for name in names:
                urls.append(f"https://{cand}.azurewebsites.net/api/{name}")
        elif provider == "gcp":
            # cand is "region:project:name" (colon-separated, since the
            # outer candidates list is itself comma-separated) or just a
            # bare "region-project" GCF hostname part.
            parts = [p.strip() for p in cand.split(":")]
            if len(parts) == 3:
                region, project, name = parts
                urls.append(f"https://{region}-{project}.cloudfunctions.net/{name}")
            else:
                for name in names:
                    urls.append(f"https://{cand}.cloudfunctions.net/{name}")

    return urls[:MAX_URLS]


def execute(
    provider: str,
    candidates: str,
    function_names: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> RawServerlessExposureResult:
    if requests is None:
        return RawServerlessExposureResult(provider=provider, error="requests library not available")

    if provider.lower() not in ("aws", "azure", "gcp"):
        return RawServerlessExposureResult(provider=provider, error=f"unsupported provider '{provider}' (use aws, azure, or gcp)")

    urls = _candidate_urls(provider, candidates, function_names)
    if not urls:
        return RawServerlessExposureResult(provider=provider, error="no candidate URLs resolved from 'candidates'")

    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tradecraft/1.0"}
    checks: List[RawFunctionCheck] = []
    for url in urls:
        try:
            resp = requests.get(url, headers=headers, timeout=timeout, verify=False)
            checks.append(RawFunctionCheck(url=url, status_code=resp.status_code, body=(resp.text or "")[:MAX_BODY_BYTES]))
        except requests.RequestException as exc:
            checks.append(RawFunctionCheck(url=url, error=str(exc)))
        except Exception as exc:
            checks.append(RawFunctionCheck(url=url, error=f"{type(exc).__name__}: {exc}"))

    return RawServerlessExposureResult(provider=provider.lower(), checks=checks)
