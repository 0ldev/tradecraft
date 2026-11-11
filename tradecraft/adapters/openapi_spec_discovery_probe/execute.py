"""
Execution logic for openapi_spec_discovery_probe: GETs a fixed, bounded
list of common OpenAPI/Swagger spec paths and parses whichever ones
resolve. No parsing of the HTTP layer beyond JSON/YAML decoding happens
here -- extracting the endpoint list from the decoded spec is parse.py's
job.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import yaml

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tradecraft/1.0"

SPEC_PATHS = (
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/openapi.json",
    "/openapi.yaml",
    "/.well-known/openapi.yaml",
    "/api-docs",
    "/api/swagger.json",
    "/api/openapi.json",
)


def normalize_base_url(target: str) -> str:
    cleaned = (target or "").strip().rstrip("/")
    if not cleaned:
        return ""
    if not (cleaned.startswith("http://") or cleaned.startswith("https://")):
        cleaned = f"https://{cleaned}"
    return cleaned


@dataclass
class SpecHit:
    path: str
    status_code: int
    spec_version: str = ""  # the 'swagger' or 'openapi' field's value
    title: str = ""
    api_version: str = ""  # the spec's own 'info.version'
    raw_spec: Dict[str, Any] = field(default_factory=dict)


@dataclass
class OpenApiSpecDiscoveryResult:
    target: str = ""
    base_url: str = ""
    hits: List[SpecHit] = field(default_factory=list)
    checked_paths: int = 0
    error: Optional[str] = None


def _try_parse_spec(body: str) -> Optional[Dict[str, Any]]:
    """Returns the decoded dict if body parses as JSON or YAML AND looks
    like an OpenAPI/Swagger document (a 'paths' key plus a 'swagger' or
    'openapi' version key) -- otherwise None."""
    data = None
    try:
        import json
        data = json.loads(body)
    except ValueError:
        try:
            data = yaml.safe_load(body)
        except yaml.YAMLError:
            return None
    if not isinstance(data, dict):
        return None
    if "paths" not in data:
        return None
    if "swagger" not in data and "openapi" not in data:
        return None
    return data


def execute(target: str, timeout: int = 10) -> OpenApiSpecDiscoveryResult:
    base_url = normalize_base_url(target)
    if not base_url:
        return OpenApiSpecDiscoveryResult(target=target, error=f"Invalid target: '{target}'")
    if requests is None:
        return OpenApiSpecDiscoveryResult(target=target, base_url=base_url, error="requests library not available")

    headers = {"User-Agent": USER_AGENT}
    result = OpenApiSpecDiscoveryResult(target=target, base_url=base_url)

    for path in SPEC_PATHS:
        result.checked_paths += 1
        try:
            resp = requests.get(f"{base_url}{path}", headers=headers, timeout=timeout, verify=False)
        except requests.RequestException:
            continue
        if resp.status_code != 200:
            continue

        spec = _try_parse_spec(resp.text)
        if spec is None:
            continue

        info = spec.get("info") or {}
        result.hits.append(SpecHit(
            path=path,
            status_code=resp.status_code,
            spec_version=str(spec.get("swagger") or spec.get("openapi") or ""),
            title=str(info.get("title", "")) if isinstance(info, dict) else "",
            api_version=str(info.get("version", "")) if isinstance(info, dict) else "",
            raw_spec=spec,
        ))

    return result
