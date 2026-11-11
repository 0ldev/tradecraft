"""
Execution logic for oauth_redirect_probe: sends a bounded fixed list of
mutated redirect_uri variants against an OAuth/OIDC authorization
endpoint and records each response for parse.py to classify. Read-only,
no login is completed -- each request is an unauthenticated GET to the
authorization endpoint itself. No parsing here -- that's parse.py's job.
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

DEFAULT_TIMEOUT = 10
MAX_BODY_BYTES = 200_000


def _mutate_redirect_uri(original: str) -> List[Dict[str, str]]:
    """A bounded, fixed set of well-known redirect_uri validation bypass
    shapes, each labeled by the technique it tests."""
    parsed = urllib.parse.urlsplit(original)
    host = parsed.hostname or ""
    scheme = parsed.scheme or "https"
    path = parsed.path or "/"

    variants = []
    if host:
        variants.append(("subdomain_trick", urllib.parse.urlunsplit((scheme, f"evil.{host}", path, "", ""))))
        variants.append(("suffix_match_bypass", urllib.parse.urlunsplit((scheme, f"{host}.evil-tradecraft-probe.test", path, "", ""))))
        variants.append(("at_bypass", f"{scheme}://{host}@evil-tradecraft-probe.test{path}"))
        variants.append(("path_traversal_suffix", urllib.parse.urlunsplit((scheme, host, path.rstrip("/") + "/../../evil-tradecraft-probe.test", "", ""))))
    if scheme == "https":
        variants.append(("scheme_downgrade", urllib.parse.urlunsplit(("http", host, path, "", ""))))
    return [{"technique": t, "redirect_uri": u} for t, u in variants]


@dataclass
class RawRedirectAttempt:
    technique: str
    redirect_uri: str
    status_code: int = 0
    location: str = ""
    body: str = ""
    error: Optional[str] = None


@dataclass
class RawOauthRedirectResult:
    target: str = ""
    original_redirect_uri: str = ""
    original_status_code: int = 0
    original_location: str = ""
    attempts: List[RawRedirectAttempt] = field(default_factory=list)
    error: Optional[str] = None


def execute(
    target: str,
    redirect_uri_param: str = "redirect_uri",
    timeout: int = DEFAULT_TIMEOUT,
) -> RawOauthRedirectResult:
    if requests is None:
        return RawOauthRedirectResult(target=target, error="requests library not available")

    parsed = urllib.parse.urlsplit(target.strip())
    query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    original_redirect_uri = query.get(redirect_uri_param, "")
    if not original_redirect_uri:
        return RawOauthRedirectResult(
            target=target,
            error=f"target URL has no '{redirect_uri_param}' query parameter to mutate",
        )

    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tradecraft/1.0"}

    def _request(redirect_uri: str):
        q = dict(query)
        q[redirect_uri_param] = redirect_uri
        new_query = urllib.parse.urlencode(q)
        url = urllib.parse.urlunsplit(parsed._replace(query=new_query))
        return requests.get(url, headers=headers, timeout=timeout, verify=False, allow_redirects=False)

    try:
        original_resp = _request(original_redirect_uri)
    except requests.RequestException as exc:
        return RawOauthRedirectResult(target=target, original_redirect_uri=original_redirect_uri, error=str(exc))
    except Exception as exc:
        return RawOauthRedirectResult(target=target, original_redirect_uri=original_redirect_uri, error=f"{type(exc).__name__}: {exc}")

    attempts: List[RawRedirectAttempt] = []
    for variant in _mutate_redirect_uri(original_redirect_uri):
        try:
            resp = _request(variant["redirect_uri"])
            attempts.append(RawRedirectAttempt(
                technique=variant["technique"], redirect_uri=variant["redirect_uri"],
                status_code=resp.status_code, location=resp.headers.get("location", ""),
                body=(resp.text or "")[:MAX_BODY_BYTES],
            ))
        except requests.RequestException as exc:
            attempts.append(RawRedirectAttempt(technique=variant["technique"], redirect_uri=variant["redirect_uri"], error=str(exc)))
        except Exception as exc:
            attempts.append(RawRedirectAttempt(technique=variant["technique"], redirect_uri=variant["redirect_uri"], error=f"{type(exc).__name__}: {exc}"))

    return RawOauthRedirectResult(
        target=target,
        original_redirect_uri=original_redirect_uri,
        original_status_code=original_resp.status_code,
        original_location=original_resp.headers.get("location", ""),
        attempts=attempts,
    )
