"""
Raw execution for hpp_probe (HTTP Parameter Pollution): sends a baseline
request, then bounded duplicate-parameter variants in both orderings
(original-then-sentinel and sentinel-then-original) for each selected
parameter. Query strings and form-encoded bodies are duplicated as pairs;
JSON-object bodies get a second key with the same name inserted at the
start or end. Only non-mutating methods (GET/HEAD/OPTIONS/POST) are
permitted, matching http_request's allowlist. No parsing here -- that's
parse.py's job.
"""
from __future__ import annotations

import json
import secrets
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tradecraft/1.0"
DEFAULT_TIMEOUT = 10
MAX_PARAMS = 5
MAX_VARIANTS = 10
MAX_BODY_BYTES = 200_000
ALLOWED_METHODS = ("GET", "HEAD", "OPTIONS", "POST")

Pair = Tuple[str, str]
BodyKind = Optional[str]  # None, "form", or "json"


@dataclass
class RawHppAttempt:
    param: str
    location: str  # "query" or "body"
    ordering: str  # "original_then_sentinel" or "sentinel_then_original"
    url: str
    body: Optional[str] = None
    sentinel: str = ""
    status_code: int = 0
    body_length: int = 0
    sentinel_reflected: bool = False
    response_changed: bool = False
    error: Optional[str] = None


@dataclass
class RawHppResult:
    target: str = ""
    method: str = "GET"
    param_names: List[str] = field(default_factory=list)
    skipped_params: List[str] = field(default_factory=list)
    baseline_status: Optional[int] = None
    baseline_length: Optional[int] = None
    attempts: List[RawHppAttempt] = field(default_factory=list)
    error: Optional[str] = None


def normalize_target_url(target: str) -> str:
    value = (target or "").strip()
    if not value:
        return ""
    if not (value.startswith("http://") or value.startswith("https://")):
        value = f"https://{value}"
    return value


def parse_custom_headers(headers_str: Optional[str]) -> Dict[str, str]:
    headers = {"User-Agent": USER_AGENT}
    if headers_str:
        for line in headers_str.splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue
            key, _, value = line.partition(":")
            headers[key.strip()] = value.strip()
    return headers


def _parse_body(body: Optional[str]) -> Tuple[BodyKind, Any]:
    if not body:
        return None, []
    stripped = body.strip()
    if stripped.startswith("{"):
        try:
            data = json.loads(stripped)
        except ValueError:
            data = None
        if isinstance(data, dict):
            return "json", list(data.keys())
    pairs = urllib.parse.parse_qsl(body, keep_blank_values=True)
    if pairs:
        return "form", pairs
    return None, []


def _duplicate_pairs(pairs: List[Pair], name: str, sentinel: str, sentinel_first: bool) -> List[Pair]:
    out: List[Pair] = []
    inserted = False
    for key, value in pairs:
        if key != name:
            out.append((key, value))
            continue
        if inserted:
            continue
        if sentinel_first:
            out.extend([(name, sentinel), (name, value)])
        else:
            out.extend([(name, value), (name, sentinel)])
        inserted = True
    return out


def _json_duplicate(body: str, name: str, sentinel: str, sentinel_first: bool) -> str:
    inner = body.strip()[1:-1].strip()
    duplicate = f"{json.dumps(name)}:{json.dumps(sentinel)}"
    if sentinel_first:
        return "{" + duplicate + ("," + inner if inner else "") + "}"
    return "{" + inner + ("," + duplicate if inner else duplicate) + "}"


def _url_with_pairs(url: str, pairs: List[Pair]) -> str:
    parsed = urllib.parse.urlsplit(url)
    query = urllib.parse.urlencode(pairs)
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment))


def _send(
    method: str,
    url: str,
    body: Optional[str],
    headers: Dict[str, str],
    timeout: int,
) -> Any:
    return requests.request(
        method,
        url,
        data=body,
        headers=headers,
        timeout=timeout,
        verify=False,
        allow_redirects=False,
    )


def execute(
    target: str,
    method: str = "GET",
    params: Optional[str] = None,
    body: Optional[str] = None,
    headers: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> RawHppResult:
    if requests is None:
        return RawHppResult(target=target, error="requests library not available")

    url = normalize_target_url(target)
    if not url:
        return RawHppResult(target=target, error="empty target URL")

    http_method = (method or "GET").upper()
    if http_method not in ALLOWED_METHODS:
        return RawHppResult(
            target=url,
            method=http_method,
            error=(
                f"method '{http_method}' is a state-mutating write/delete and not "
                "permitted via hpp_probe (allowed: GET, HEAD, OPTIONS, POST). "
                "Use the destructive http_write_request tool (requires "
                "--allow-destructive) for PUT, DELETE, or PATCH."
            ),
        )
    req_headers = parse_custom_headers(headers)
    body_kind, body_data = _parse_body(body)
    if body_kind == "json":
        req_headers.setdefault("Content-Type", "application/json")
        body_keys = list(body_data)
        body_pairs: List[Pair] = []
    elif body_kind == "form":
        req_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        body_pairs = list(body_data)
        body_keys = [k for k, _ in body_pairs]
    else:
        body_pairs = []
        body_keys = []

    parsed = urllib.parse.urlsplit(url)
    query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True) if parsed.query else []
    query_keys = [k for k, _ in query_pairs]

    requested = [p.strip() for p in (params or "").split(",") if p.strip()]
    if requested:
        candidate_names = requested
    else:
        candidate_names = list(dict.fromkeys(query_keys + body_keys))
    candidate_names = candidate_names[:MAX_PARAMS]
    if not candidate_names:
        return RawHppResult(
            target=url,
            method=http_method,
            error="no parameters to pollute; supply 'params' or include at least one query/form/JSON key",
        )

    try:
        baseline = _send(http_method, url, body, req_headers, timeout)
    except requests.RequestException as exc:
        return RawHppResult(target=url, method=http_method, error=str(exc))

    result = RawHppResult(
        target=url,
        method=http_method,
        param_names=candidate_names,
        baseline_status=baseline.status_code,
        baseline_length=len(baseline.content),
    )

    attempts: List[RawHppAttempt] = []
    for name in candidate_names:
        in_query = name in query_keys
        in_body = name in body_keys
        if not in_query and not in_body:
            result.skipped_params.append(name)
            continue

        for sentinel_first in (False, True):
            if len(attempts) >= MAX_VARIANTS:
                break
            sentinel = f"rs_hpp_{secrets.token_hex(4)}"
            ordering = "sentinel_then_original" if sentinel_first else "original_then_sentinel"
            if in_query:
                variant_pairs = _duplicate_pairs(query_pairs, name, sentinel, sentinel_first)
                attempt = RawHppAttempt(
                    param=name,
                    location="query",
                    ordering=ordering,
                    url=_url_with_pairs(url, variant_pairs),
                    sentinel=sentinel,
                )
                attempts.append(attempt)
            if in_body and len(attempts) < MAX_VARIANTS:
                if body_kind == "json":
                    variant_body = _json_duplicate(body or "{}", name, sentinel, sentinel_first)
                else:
                    variant_body = urllib.parse.urlencode(
                        _duplicate_pairs(body_pairs, name, sentinel, sentinel_first)
                    )
                attempts.append(
                    RawHppAttempt(
                        param=name,
                        location="body",
                        ordering=ordering,
                        url=url,
                        body=variant_body,
                        sentinel=sentinel,
                    )
                )
        if len(attempts) >= MAX_VARIANTS:
            break

    for attempt in attempts:
        try:
            resp = _send(http_method, attempt.url, attempt.body, req_headers, timeout)
        except requests.RequestException as exc:
            attempt.error = str(exc)
            continue
        attempt.status_code = resp.status_code
        attempt.body_length = len(resp.content)
        text = (resp.text or "")[:MAX_BODY_BYTES]
        # The sentinel is unique per attempt, so finding this attempt's own
        # value in the response is a real signal that it reached
        # server-side handling (not an incidental echo of the baseline).
        attempt.sentinel_reflected = bool(attempt.sentinel and attempt.sentinel in text)
        attempt.response_changed = (
            resp.status_code != result.baseline_status
            or len(resp.content) != result.baseline_length
        )

    result.attempts = attempts
    return result
