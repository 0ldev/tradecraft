"""
Execution logic for host_header_injection_probe: sends one request per
candidate header, each carrying a unique marker domain, and records the
raw response for parse.py to check for reflection into an absolute-URL
context (password-reset-link poisoning). Read-only -- no parsing here.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Dict, List, Optional

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None

DEFAULT_TIMEOUT = 10
DEFAULT_HEADERS_TO_TEST = ("Host", "X-Forwarded-Host", "X-Forwarded-Server", "X-Host")
MAX_BODY_BYTES = 200_000


@dataclass
class RawHeaderAttempt:
    header: str
    marker_domain: str
    status_code: int = 0
    location: str = ""
    body: str = ""
    error: Optional[str] = None


@dataclass
class RawHostHeaderResult:
    target: str = ""
    method: str = ""
    attempts: List[RawHeaderAttempt] = field(default_factory=list)
    error: Optional[str] = None


def normalize_target_url(target: str) -> str:
    t = target.strip()
    if not t:
        return ""
    if not (t.startswith("http://") or t.startswith("https://")):
        t = f"https://{t}"
    return t


def execute(
    target: str,
    method: str = "GET",
    body: Optional[str] = None,
    headers_to_test: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> RawHostHeaderResult:
    if requests is None:
        return RawHostHeaderResult(target=target, error="requests library not available")

    url = normalize_target_url(target)
    if not url:
        return RawHostHeaderResult(target=target, error="empty target URL")

    http_method = (method or "GET").upper()
    header_names = [h.strip() for h in (headers_to_test or ",".join(DEFAULT_HEADERS_TO_TEST)).split(",") if h.strip()]

    attempts: List[RawHeaderAttempt] = []
    for header_name in header_names:
        marker = f"rs-{secrets.token_hex(4)}.attacker-controlled.test"
        req_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tradecraft/1.0",
            header_name: marker,
        }
        try:
            kwargs = dict(headers=req_headers, timeout=timeout, verify=False, allow_redirects=False)
            if http_method != "GET" and body:
                kwargs["data"] = body
            resp = requests.request(http_method, url, **kwargs)
            attempts.append(RawHeaderAttempt(
                header=header_name, marker_domain=marker,
                status_code=resp.status_code,
                location=resp.headers.get("location", ""),
                body=(resp.text or "")[:MAX_BODY_BYTES],
            ))
        except requests.RequestException as exc:
            attempts.append(RawHeaderAttempt(header=header_name, marker_domain=marker, error=str(exc)))
        except Exception as exc:
            attempts.append(RawHeaderAttempt(header=header_name, marker_domain=marker, error=f"{type(exc).__name__}: {exc}"))

    return RawHostHeaderResult(target=url, method=http_method, attempts=attempts)
