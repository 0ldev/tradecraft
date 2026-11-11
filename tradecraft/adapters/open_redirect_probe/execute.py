"""
Raw execution for open_redirect_probe: replaces candidate redirect-controlling
query parameters with payloads pointing at a non-resolving canary host and
records the response status and Location header. Redirects are never
followed. No parsing here -- parse.py's job.
"""
from __future__ import annotations

import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tradecraft/1.0"

CANARY_HOST = "tradecraft-oob-canary.invalid"

REDIRECT_PARAM_NAMES = {
    "redirect", "redirect_uri", "redirect_url", "return", "returnurl",
    "return_url", "returnto", "next", "continue", "dest", "destination",
    "redir", "url", "target", "out", "view", "r", "goto", "forward",
    "forward_url", "callback", "callbackurl", "success_url",
    "checkout_url",
}

# (label, template). "{c}" is CANARY_HOST, "{host}" is the target's hostname.
PAYLOAD_TEMPLATES = [
    ("plain_https", "https://{c}/"),
    ("no_trailing_slash", "https://{c}"),
    ("protocol_relative", "//{c}/"),
    ("triple_slash", "///{c}/"),
    ("missing_slashes", "https:{c}"),
    ("backslash_trick", "/\\{c}/"),
    ("userinfo_trick", "https://{host}@{c}/"),
    ("reversed_userinfo", "https://{c}\\@{host}/"),
    ("subdomain_confusion", "https://{host}.{c}/"),
    ("leading_whitespace", " https://{c}/"),
]


@dataclass
class ParamAttempt:
    param: str
    payload_label: str
    payload: str
    status: Optional[int] = None
    location: str = ""
    redirects_to_canary: bool = False
    error: Optional[str] = None


@dataclass
class RawOpenRedirectResult:
    target: str = ""
    tested_params: List[str] = field(default_factory=list)
    attempts: List[ParamAttempt] = field(default_factory=list)
    error: Optional[str] = None


def normalize_target_url(target: str) -> str:
    """Ensure target has a valid HTTP/HTTPS scheme."""
    t = target.strip()
    if not t:
        return ""
    if not (t.startswith("http://") or t.startswith("https://")):
        t = f"https://{t}"
    return t


def execute(target: str, param: str = "", timeout: int = 10) -> RawOpenRedirectResult:
    if requests is None:
        return RawOpenRedirectResult(target=target, error="requests library not available")

    url = normalize_target_url(target)
    if not url:
        return RawOpenRedirectResult(target=target, error="empty target URL")

    parsed = urllib.parse.urlsplit(url)
    # keep_blank_values: an empty ?next= is still a redirect parameter worth testing.
    qs: Dict[str, str] = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    if not qs:
        return RawOpenRedirectResult(target=url, error="target has no query parameters to test")

    if param:
        if param not in qs:
            return RawOpenRedirectResult(
                target=url,
                error=f"'{param}' is not a query parameter on target",
            )
        tested = [param]
    else:
        tested = [k for k in qs if k.lower() in REDIRECT_PARAM_NAMES]
        if not tested:
            tested = list(qs.keys())

    result = RawOpenRedirectResult(target=url, tested_params=list(tested))
    host = parsed.hostname or ""
    headers = {"User-Agent": USER_AGENT}

    for name in tested:
        for label, template in PAYLOAD_TEMPLATES:
            payload = template.format(c=CANARY_HOST, host=host)
            attempt = ParamAttempt(param=name, payload_label=label, payload=payload)
            mutated = dict(qs)
            mutated[name] = payload
            request_url = urllib.parse.urlunsplit(
                (parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(mutated), parsed.fragment)
            )
            try:
                resp = requests.get(
                    request_url,
                    headers=headers,
                    timeout=timeout,
                    verify=False,
                    allow_redirects=False,
                )
                attempt.status = resp.status_code
                attempt.location = resp.headers.get("Location", "")
                attempt.redirects_to_canary = (
                    urllib.parse.urlsplit(attempt.location).hostname == CANARY_HOST
                )
            except requests.RequestException as exc:
                attempt.error = str(exc)
            result.attempts.append(attempt)

    return result
