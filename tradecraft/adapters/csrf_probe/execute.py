"""
Execution logic for csrf_probe: sends exactly 2 extra write attempts
against a state-changing endpoint, beyond whatever the operator already
knows works -- (a) the token field removed, (b) the token replaced by a
random same-shaped value -- both without the usual same-origin
Referer/Origin headers. Each call is a genuine write against live
state. No parsing here -- that's parse.py's job.
"""
from __future__ import annotations

import json
import secrets
from dataclasses import dataclass, field
from typing import Dict, List, Optional

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None

DEFAULT_TIMEOUT = 10


@dataclass
class RawCsrfAttempt:
    variant: str  # "token_removed" or "token_replaced"
    status_code: int = 0
    body: str = ""
    error: Optional[str] = None


@dataclass
class RawCsrfProbeResult:
    target: str = ""
    method: str = ""
    attempts: List[RawCsrfAttempt] = field(default_factory=list)
    error: Optional[str] = None


def parse_custom_headers(headers_str: Optional[str]) -> Dict[str, str]:
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tradecraft/1.0"}
    if headers_str:
        for line in headers_str.splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue
            k, _, v = line.partition(":")
            headers[k.strip()] = v.strip()
    # Strip any Referer/Origin the operator may have carried over -- the
    # whole point is to probe a cross-origin-shaped request.
    headers.pop("Referer", None)
    headers.pop("Origin", None)
    return headers


def _strip_token(body: Dict, token_param: str) -> Dict:
    stripped = dict(body)
    stripped.pop(token_param, None)
    return stripped


def _replace_token(body: Dict, token_param: str) -> Dict:
    replaced = dict(body)
    original = str(body.get(token_param, ""))
    replaced[token_param] = secrets.token_hex(max(8, len(original) // 2)) if original else secrets.token_hex(16)
    return replaced


def execute(
    target: str,
    body: str,
    token_param: str,
    method: str = "POST",
    headers: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> RawCsrfProbeResult:
    if requests is None:
        return RawCsrfProbeResult(target=target, error="requests library not available")

    try:
        baseline_body = json.loads(body) if body else {}
        if not isinstance(baseline_body, dict):
            raise ValueError("body must decode to a JSON object")
    except Exception as exc:
        return RawCsrfProbeResult(target=target, error=f"invalid 'body' JSON: {exc}")

    http_method = (method or "POST").upper()
    req_headers = parse_custom_headers(headers)

    variants = [
        ("token_removed", _strip_token(baseline_body, token_param)),
        ("token_replaced", _replace_token(baseline_body, token_param)),
    ]

    attempts: List[RawCsrfAttempt] = []
    for variant_name, variant_body in variants:
        try:
            resp = requests.request(
                http_method, target, json=variant_body, headers=req_headers,
                timeout=timeout, verify=False, allow_redirects=True,
            )
            attempts.append(RawCsrfAttempt(variant=variant_name, status_code=resp.status_code, body=(resp.text or "")[:5000]))
        except requests.RequestException as exc:
            attempts.append(RawCsrfAttempt(variant=variant_name, error=str(exc)))
        except Exception as exc:
            attempts.append(RawCsrfAttempt(variant=variant_name, error=f"{type(exc).__name__}: {exc}"))

    return RawCsrfProbeResult(target=target, method=http_method, attempts=attempts)
