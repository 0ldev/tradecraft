"""
Raw execution for api_version_shadow_probe: takes one endpoint that is
expected to require authentication, sends it unauthenticated as a baseline,
then retries it under a bounded set of old/alternate version prefixes. A
shadow/zombie version that answers 2xx without credentials is the finding
(OWASP API9:2023, Improper Inventory Management). Read-only; no credentials
are sent. No parsing here -- that's parse.py's job.
"""
from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tradecraft/1.0"
MAX_VARIANTS = 12
BLOCKED_STATUSES = (401, 403)
ALLOWED_METHODS = ("GET", "HEAD", "OPTIONS", "POST")
_VERSION_SEGMENT = re.compile(r"(?i)^v\d+(?:\.\d+)?$")
VERSION_ALTERNATIVES = ("v1", "v2", "v3", "v4", "v5", "v0", "beta", "legacy", "internal")


@dataclass
class RawApiVersionVariant:
    label: str
    url: str
    status: Optional[int] = None
    body_length: Optional[int] = None
    location: str = ""
    error: Optional[str] = None


@dataclass
class RawApiVersionShadowResult:
    target: str = ""
    method: str = "GET"
    baseline_status: Optional[int] = None
    baseline_length: Optional[int] = None
    baseline_was_blocked: bool = False
    baseline_already_open: bool = False
    variants: List[RawApiVersionVariant] = field(default_factory=list)
    error: Optional[str] = None


def normalize_target_url(target: str) -> str:
    value = (target or "").strip()
    if not value:
        return ""
    if not (value.startswith("http://") or value.startswith("https://")):
        value = f"https://{value}"
    return value


def _path_from_segments(segments: List[str]) -> str:
    cleaned = [s for s in segments if s]
    return "/" + "/".join(cleaned)


def build_version_variants(url: str) -> List[Tuple[str, str]]:
    """Returns (label, variant_url) pairs, deduplicated and capped at
    MAX_VARIANTS. Never includes the original URL itself."""
    parsed = urllib.parse.urlsplit(url)
    path = parsed.path or "/"
    query = f"?{parsed.query}" if parsed.query else ""
    segments = path.split("/")
    version_index = next(
        (i for i, segment in enumerate(segments) if _VERSION_SEGMENT.match(segment)),
        None,
    )

    paths: List[Tuple[str, str]] = []
    if version_index is not None:
        current = segments[version_index]
        prefix = segments[:version_index]
        tail = segments[version_index + 1 :]
        for alt in VERSION_ALTERNATIVES:
            if alt.lower() == current.lower():
                continue
            paths.append((f"replace_{current.lower()}_with_{alt}", _path_from_segments(prefix + [alt] + tail)))
        # /api/legacy/<resource> is a common zombie prefix even when the
        # current path is /v2/<resource> rather than /api/v2/<resource>.
        if not (prefix and prefix[-1].lower() == "api"):
            paths.append(("api_legacy_prefix", _path_from_segments(["api", "legacy"] + tail)))
    else:
        resource = [s for s in segments if s]
        for label, new_path in (
            ("api_v1_prefix", _path_from_segments(["api", "v1"] + resource)),
            ("v1_prefix", _path_from_segments(["v1"] + resource)),
            ("api_legacy_prefix", _path_from_segments(["api", "legacy"] + resource)),
            ("legacy_prefix", _path_from_segments(["legacy"] + resource)),
            ("api_prefix", _path_from_segments(["api"] + resource)),
        ):
            paths.append((label, new_path))

    result: List[Tuple[str, str]] = []
    seen = {path}
    for label, new_path in paths:
        if new_path in seen:
            continue
        seen.add(new_path)
        variant_url = f"{parsed.scheme}://{parsed.netloc}{new_path}{query}"
        result.append((label, variant_url))
        if len(result) >= MAX_VARIANTS:
            break
    return result


def execute(
    target: str,
    method: str = "GET",
    body: Optional[str] = None,
    timeout: int = 10,
) -> RawApiVersionShadowResult:
    if requests is None:
        return RawApiVersionShadowResult(target=target, error="requests library not available")

    url = normalize_target_url(target)
    if not url:
        return RawApiVersionShadowResult(target=target, error="empty target URL")

    http_method = (method or "GET").upper()
    if http_method not in ALLOWED_METHODS:
        return RawApiVersionShadowResult(
            target=url,
            method=http_method,
            error=(
                f"method '{http_method}' is a state-mutating write/delete and not "
                "permitted via api_version_shadow_probe (allowed: GET, HEAD, "
                "OPTIONS, POST). Use the destructive http_write_request tool "
                "(requires --allow-destructive) for PUT, DELETE, or PATCH."
            ),
        )
    headers = {"User-Agent": USER_AGENT}
    request_kwargs: Dict[str, object] = {
        "headers": headers,
        "timeout": timeout,
        "verify": False,
        "allow_redirects": False,
    }
    if body and http_method != "GET":
        request_kwargs["data"] = body

    try:
        baseline = requests.request(http_method, url, **request_kwargs)
    except requests.RequestException as exc:
        return RawApiVersionShadowResult(target=url, method=http_method, error=str(exc))

    baseline_length = len(baseline.content)
    result = RawApiVersionShadowResult(
        target=url,
        method=http_method,
        baseline_status=baseline.status_code,
        baseline_length=baseline_length,
        baseline_was_blocked=baseline.status_code in BLOCKED_STATUSES,
    )

    if baseline.status_code not in BLOCKED_STATUSES:
        result.baseline_already_open = 200 <= baseline.status_code < 300
        return result

    for label, variant_url in build_version_variants(url):
        attempt = RawApiVersionVariant(label=label, url=variant_url)
        try:
            resp = requests.request(http_method, variant_url, **request_kwargs)
            attempt.status = resp.status_code
            attempt.body_length = len(resp.content)
            attempt.location = resp.headers.get("location", "")
        except requests.RequestException as exc:
            attempt.error = str(exc)
        result.variants.append(attempt)

    return result
