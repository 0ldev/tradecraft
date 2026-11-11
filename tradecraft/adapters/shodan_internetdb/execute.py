"""
Execution for Shodan InternetDB lookup.
Free, unauthenticated API: https://internetdb.shodan.io/<ip>
"""
from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import requests

API_BASE = "https://internetdb.shodan.io"


@dataclass
class RawShodanResult:
    ip: str
    found: bool = False
    body: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


def normalize_ips(ip_str: str) -> List[str]:
    """Comma-split/trim/dedupe, then drop (don't raise on) anything that
    doesn't parse via ipaddress.ip_address() -- same 'skip the bad one,
    don't abort the batch' discipline retire_js's download_scripts()
    already uses for its own per-item failures."""
    seen = set()
    valid_ips = []
    for raw in ip_str.split(","):
        s = raw.strip()
        if not s or s in seen:
            continue
        try:
            ipaddress.ip_address(s)
            seen.add(s)
            valid_ips.append(s)
        except ValueError:
            continue
    return valid_ips


def query_one(ip: str, timeout: int = 10) -> RawShodanResult:
    """requests.get(f"{API_BASE}/{ip}", timeout=timeout). 200 ->
    RawShodanResult(ip=ip, found=True, body=resp.json()). 404 ->
    RawShodanResult(ip=ip, found=False, body=None) -- a normal, common
    outcome, not an error. Anything else (other status, a
    requests.RequestException) -> RawShodanResult(ip=ip, error=...)."""
    try:
        resp = requests.get(f"{API_BASE}/{ip}", timeout=timeout)
        if resp.status_code == 200:
            return RawShodanResult(ip=ip, found=True, body=resp.json())
        if resp.status_code == 404:
            return RawShodanResult(ip=ip, found=False, body=None)
        return RawShodanResult(ip=ip, error=f"HTTP {resp.status_code}: {resp.text[:200]}")
    except requests.RequestException as exc:
        return RawShodanResult(ip=ip, error=str(exc))


def execute(ip: str, timeout: int = 10) -> List[RawShodanResult]:
    """One query_one() per normalize_ips() entry, sequential with a
    small (0.2s) time.sleep between calls -- courtesy to a free public
    API, not a documented hard limit, so this is a 'be a good citizen'
    choice, not a correctness requirement."""
    ips = normalize_ips(ip)
    if not ips:
        return [RawShodanResult(ip=ip, error="no valid IP address provided")]
    results = []
    for idx, addr in enumerate(ips):
        if idx > 0:
            time.sleep(0.2)
        results.append(query_one(addr, timeout=timeout))
    return results
