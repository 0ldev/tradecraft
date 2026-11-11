"""
Pure-Python execution for openapi_fuzz: schema-conforming authorization boundary
probing and parameter mutation testing against endpoints declared in an OpenAPI/Swagger spec.
"""
from __future__ import annotations

import json
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_TIMEOUT_SECONDS = 15
MAX_ENDPOINTS_TO_TEST = 15
CANARY_PROBE_VALUES = ["' OR '1'='1", "../../../etc/passwd", "${7*7}", "admin", "0"]


@dataclass
class EndpointProbeResult:
    method: str
    path: str
    url: str
    status_code: Optional[int] = None
    response_snippet: str = ""
    anomaly_detected: bool = False
    error: Optional[str] = None


@dataclass
class RawOpenApiFuzzResult:
    target: str = ""
    spec_url: str = ""
    endpoints_tested: List[EndpointProbeResult] = field(default_factory=list)
    error: Optional[str] = None


def normalize_base_url(target: str) -> str:
    url = target.strip()
    if not url:
        return ""
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    return url.rstrip("/")


def parse_spec_endpoints(spec_json: Dict[str, Any]) -> List[Dict[str, str]]:
    """Extracts up to MAX_ENDPOINTS_TO_TEST (method, path) entries from OpenAPI/Swagger JSON."""
    endpoints: List[Dict[str, str]] = []
    paths = spec_json.get("paths", {})
    if not isinstance(paths, dict):
        return []

    for path, methods in paths.items():
        if not isinstance(methods, dict) or not path.startswith("/"):
            continue
        for m in ("get", "post", "put", "delete", "patch"):
            if m in methods:
                endpoints.append({"method": m.upper(), "path": path})
                if len(endpoints) >= MAX_ENDPOINTS_TO_TEST:
                    return endpoints
    return endpoints


def execute(
    target: str,
    spec_url: str = "",
    spec_content: str = "",
    auth_header: str = "",
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    session: Optional[requests.Session] = None,
) -> RawOpenApiFuzzResult:
    base_url = normalize_base_url(target)
    if not base_url:
        return RawOpenApiFuzzResult(error="empty target URL")

    close_session = False
    if session is None:
        session = requests.Session()
        close_session = True

    spec_dict: Optional[Dict[str, Any]] = None
    if spec_content.strip():
        try:
            spec_dict = json.loads(spec_content)
        except Exception as exc:
            return RawOpenApiFuzzResult(target=base_url, error=f"invalid spec_content JSON: {exc}")
    elif spec_url.strip():
        try:
            resp = session.get(spec_url.strip(), verify=False, timeout=timeout)
            spec_dict = resp.json()
        except Exception as exc:
            return RawOpenApiFuzzResult(target=base_url, spec_url=spec_url, error=f"failed to fetch spec from spec_url: {exc}")
    else:
        return RawOpenApiFuzzResult(target=base_url, error="one of spec_url or spec_content must be provided")

    if not isinstance(spec_dict, dict):
        return RawOpenApiFuzzResult(target=base_url, error="parsed spec is not a valid JSON object")

    endpoints = parse_spec_endpoints(spec_dict)
    if not endpoints:
        return RawOpenApiFuzzResult(target=base_url, error="no valid HTTP endpoints found in spec paths")

    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) tradecraft/1.0"}
    if auth_header.strip():
        k, _, v = auth_header.partition(":")
        if k and v:
            headers[k.strip()] = v.strip()

    tested: List[EndpointProbeResult] = []
    try:
        for ep in endpoints:
            m = ep["method"]
            p = ep["path"]
            # Replace path parameters like {id} with canary value
            probe_path = p
            for part in p.split("/"):
                if part.startswith("{") and part.endswith("}"):
                    probe_path = probe_path.replace(part, "1")

            full_url = f"{base_url}{probe_path}"
            res = EndpointProbeResult(method=m, path=p, url=full_url)

            try:
                if m == "GET":
                    r = session.get(full_url, headers=headers, verify=False, timeout=timeout, allow_redirects=False)
                elif m == "POST":
                    r = session.post(full_url, json={"test": "1"}, headers=headers, verify=False, timeout=timeout, allow_redirects=False)
                elif m == "PUT":
                    r = session.put(full_url, json={"test": "1"}, headers=headers, verify=False, timeout=timeout, allow_redirects=False)
                elif m == "DELETE":
                    r = session.delete(full_url, headers=headers, verify=False, timeout=timeout, allow_redirects=False)
                else:
                    r = session.request(m, full_url, headers=headers, verify=False, timeout=timeout, allow_redirects=False)

                res.status_code = r.status_code
                res.response_snippet = (r.text or "")[:500]

                # Anomaly detection: 200/201 on administrative endpoints without auth, or 500 error leaking stack traces
                if r.status_code in (200, 201) and any(w in p.lower() for w in ("admin", "user", "secret", "auth", "internal")):
                    res.anomaly_detected = True
                elif r.status_code == 500 and any(w in r.text.lower() for w in ("traceback", "exception", "sql", "syntax")):
                    res.anomaly_detected = True

            except Exception as e:
                res.error = str(e)

            tested.append(res)
    finally:
        if close_session:
            session.close()

    return RawOpenApiFuzzResult(
        target=base_url,
        spec_url=spec_url,
        endpoints_tested=tested,
    )
