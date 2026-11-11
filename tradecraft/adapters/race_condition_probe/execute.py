"""
Raw execution for race_condition_probe: fires a bounded burst of identical
HTTP requests at one URL using a thread pool, to detect a TOCTOU race
condition (e.g. a single-use coupon redeemable more than once).

HONESTY NOTE: this uses concurrent.futures.ThreadPoolExecutor to fire
requests as close to simultaneously as Python's GIL and the OS scheduler
allow. This is a best-effort approximation of a true race window, NOT a
guaranteed single-packet/HTTP-2-multiplexed race primitive (unlike
specialized tools such as Burp's Turbo Intruder). A negative result here
does not prove the endpoint is safe against a stronger race technique --
only that this specific, honestly-labeled best-effort burst did not
surface a double-success.

Hard cap, independent of --allow-destructive: MAX_REQUESTS requests per
call. A real limited resource (a coupon, a rate-limit counter) may be
genuinely consumed by this call -- there is no undo.
"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tradecraft/1.0"

# Hard cap on requests per call -- never affected by --allow-destructive.
MAX_REQUESTS = 20
DEFAULT_REQUESTS = 5


@dataclass
class RaceAttempt:
    index: int
    status_code: Optional[int] = None
    body_snippet: str = ""
    success_marker_found: bool = False
    duration_seconds: float = 0.0
    error: Optional[str] = None


@dataclass
class RawRaceConditionResult:
    url: str = ""
    method: str = ""
    requested_count: int = 0
    attempts: List[RaceAttempt] = field(default_factory=list)
    success_count: int = 0
    likely_race_condition: bool = False
    error: Optional[str] = None


def _normalize_url(url: str) -> str:
    cleaned = (url or "").strip()
    if not cleaned:
        return ""
    if not (cleaned.startswith("http://") or cleaned.startswith("https://")):
        cleaned = f"https://{cleaned}"
    return cleaned


def _fire_one(
    index: int,
    url: str,
    method: str,
    headers: Optional[Dict[str, str]],
    data: Optional[str],
    timeout: int,
    success_marker: Optional[str],
) -> RaceAttempt:
    attempt = RaceAttempt(index=index)
    t0 = time.time()
    try:
        resp = requests.request(
            method,
            url,
            headers=headers,
            data=data,
            timeout=timeout,
            verify=False,
        )
        attempt.duration_seconds = round(time.time() - t0, 3)
        attempt.status_code = resp.status_code
        body = resp.text or ""
        attempt.body_snippet = body[:500]
        if success_marker:
            attempt.success_marker_found = success_marker in body
        else:
            # No marker given: treat any 2xx as a "success-shaped" response.
            attempt.success_marker_found = 200 <= resp.status_code < 300
    except requests.RequestException as exc:
        attempt.duration_seconds = round(time.time() - t0, 3)
        attempt.error = str(exc)
    return attempt


def execute(
    url: str,
    method: str = "POST",
    headers: Optional[str] = None,
    data: Optional[str] = None,
    request_count: int = DEFAULT_REQUESTS,
    success_marker: Optional[str] = None,
    timeout: int = 10,
) -> RawRaceConditionResult:
    target_url = _normalize_url(url)
    if not target_url:
        return RawRaceConditionResult(error="empty url provided")
    if requests is None:
        return RawRaceConditionResult(url=target_url, error="requests library not available")

    http_method = (method or "POST").strip().upper()
    count = max(2, min(int(request_count or DEFAULT_REQUESTS), MAX_REQUESTS))

    header_dict: Dict[str, str] = {"User-Agent": USER_AGENT}
    if headers:
        for line in headers.splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue
            k, _, v = line.partition(":")
            header_dict[k.strip()] = v.strip()

    result = RawRaceConditionResult(url=target_url, method=http_method, requested_count=count)

    with ThreadPoolExecutor(max_workers=count) as pool:
        futures = [
            pool.submit(_fire_one, i, target_url, http_method, header_dict, data, timeout, success_marker)
            for i in range(count)
        ]
        attempts = [f.result() for f in futures]

    attempts.sort(key=lambda a: a.index)
    result.attempts = attempts
    result.success_count = sum(1 for a in attempts if a.success_marker_found)
    # More than one "success" out of a burst meant to exercise a
    # single-use/limited resource is the race-condition signal.
    result.likely_race_condition = result.success_count > 1

    return result
