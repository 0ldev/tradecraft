"""
Raw execution for response_security_audit: a single GET fetches the page
once, and its response (headers, Set-Cookie lines, and HTML body) is
reused for three separate audits (cookie security, security headers, and
subresource integrity) instead of each fetching the same URL on its own.
No parsing here -- that's parse.py's job.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None

MAX_BODY_BYTES = 2_000_000


@dataclass
class RawResponseAuditResult:
    target: str = ""
    final_url: Optional[str] = None
    is_https: bool = False
    # Lower-cased header name -> value, from the final response only.
    headers: Dict[str, str] = field(default_factory=dict)
    # Raw Set-Cookie header lines, from redirect history then the final response.
    set_cookie_lines: List[str] = field(default_factory=list)
    # HTML body (capped), used to find <script src> / <link rel=stylesheet href>.
    body: str = ""
    error: Optional[str] = None


def normalize_target_url(target: str) -> str:
    """Ensure target has a valid HTTP/HTTPS scheme."""
    t = target.strip()
    if not t:
        return ""
    if not (t.startswith("http://") or t.startswith("https://")):
        t = f"https://{t}"
    return t


def execute(target: str, timeout: int = 15, max_body_bytes: int = MAX_BODY_BYTES) -> RawResponseAuditResult:
    if requests is None:
        return RawResponseAuditResult(target=target, error="requests library not available")

    url = normalize_target_url(target)
    if not url:
        return RawResponseAuditResult(target=target, error="empty target URL")

    try:
        resp = requests.get(
            url,
            timeout=timeout,
            verify=False,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tradecraft/1.0"},
        )
    except requests.RequestException as exc:
        return RawResponseAuditResult(target=url, error=str(exc))
    except Exception as exc:
        return RawResponseAuditResult(target=url, error=f"{type(exc).__name__}: {exc}")

    final_url = resp.url
    is_https = final_url.lower().startswith("https://")
    headers = {str(k).lower(): str(v) for k, v in resp.headers.items()}

    # Check redirect history for intermediate Set-Cookie headers (e.g. auth
    # 302 redirects), then the final response.
    raw_cookie_lines: List[str] = []
    if hasattr(resp, "history"):
        for h in resp.history:
            if hasattr(h, "raw") and hasattr(h.raw, "headers") and hasattr(h.raw.headers, "getlist"):
                raw_cookie_lines.extend(h.raw.headers.getlist("Set-Cookie"))
    if hasattr(resp, "raw") and hasattr(resp.raw, "headers") and hasattr(resp.raw.headers, "getlist"):
        raw_cookie_lines.extend(resp.raw.headers.getlist("Set-Cookie"))

    body = resp.text[:max_body_bytes]

    return RawResponseAuditResult(
        target=url,
        final_url=final_url,
        is_https=is_https,
        headers=headers,
        set_cookie_lines=raw_cookie_lines,
        body=body,
    )
