"""
Execution logic for crlf_injection_probe: injects a CRLF ("%0d%0a") plus a
fake header line into one query parameter, then inspects the ACTUAL
response headers (as parsed by requests/urllib3, which correctly splits
genuinely distinct header lines arriving over the wire) for a header line
that should not exist. Relies on the HTTP client's own header parsing to
detect a genuinely distinct injected header line; a server that folds the
injected sequence some other way is a documented limitation, not a
correctness bug here.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Dict, Optional
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode, quote

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tradecraft/1.0"
DEFAULT_INJECTED_HEADER_NAME = "X-Tradecraft-CRLF-Test"


@dataclass
class RawCrlfResult:
    target: str = ""
    parameter: str = ""
    injected_header_name: str = ""
    marker: str = ""
    probe_url: str = ""
    status_code: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    injected_header_found: bool = False
    injected_value_in_other_header: Optional[str] = None
    error: Optional[str] = None


def normalize_target_url(url: str) -> str:
    cleaned = (url or "").strip()
    if not cleaned:
        return ""
    if not (cleaned.startswith("http://") or cleaned.startswith("https://")):
        cleaned = f"https://{cleaned}"
    return cleaned


def build_probe_url(target_url: str, parameter: str, injected_header_name: str, marker: str) -> str:
    parsed = urlparse(target_url)
    qs = dict(parse_qsl(parsed.query, keep_blank_values=True))
    payload = f"https://example.com%0d%0a{injected_header_name}:%20{marker}"
    qs[parameter] = payload
    new_query = urlencode(qs, safe="%", quote_via=quote)
    return urlunparse(parsed._replace(query=new_query))


def execute(
    target: str,
    parameter: str,
    injected_header_name: str = DEFAULT_INJECTED_HEADER_NAME,
    timeout: int = 10,
) -> RawCrlfResult:
    target_url = normalize_target_url(target)
    header_name = injected_header_name or DEFAULT_INJECTED_HEADER_NAME
    result = RawCrlfResult(target=target_url, parameter=parameter, injected_header_name=header_name)
    if not target_url:
        result.error = "empty target URL"
        return result
    if not parameter:
        result.error = "missing required parameter"
        return result
    if requests is None:
        result.error = "requests library not available"
        return result

    marker = "crlf" + secrets.token_hex(8)
    result.marker = marker
    probe_url = build_probe_url(target_url, parameter, header_name, marker)
    result.probe_url = probe_url

    try:
        resp = requests.get(
            probe_url,
            headers={"User-Agent": USER_AGENT},
            timeout=timeout,
            verify=False,
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        result.error = f"probe request failed: {exc}"
        return result

    result.status_code = resp.status_code
    result.headers = dict(resp.headers)

    for key, value in result.headers.items():
        if key.lower() == header_name.lower() and marker in value:
            result.injected_header_found = True
            break

    if not result.injected_header_found:
        for key, value in result.headers.items():
            if marker in value:
                result.injected_value_in_other_header = key
                break

    return result
