"""
Pure parsing for response_security_audit: cookie-flag scoring, HTTP
security-header scoring, and Subresource Integrity (SRI) asset scoring --
all derived from one already-fetched response (see execute.py). No
subprocess, no I/O.
"""
from __future__ import annotations

import urllib.parse
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Tuple

from tradecraft.adapters.response_security_audit.execute import RawResponseAuditResult

# ---------------------------------------------------------------- cookies

SESSION_NAME_MARKERS = ("sess", "auth", "token", "sid", "csrf", "forgery", "login", "remember", "jwt")


def looks_like_session_cookie(name: str) -> bool:
    """Return True if the cookie name contains a known session/auth substring."""
    name_lower = name.lower()
    return any(marker in name_lower for marker in SESSION_NAME_MARKERS)


def parse_cookie_line(raw_header: str) -> Dict[str, Any]:
    """Parse a single Set-Cookie header into name, flags, and attributes."""
    segments = [s.strip() for s in raw_header.split(";") if s.strip()]
    if not segments:
        return {"name": "", "secure": False, "httponly": False, "samesite": None, "raw": raw_header}

    first = segments[0]
    name = first.split("=", 1)[0].strip()
    rest = segments[1:]

    has_secure = any(seg.lower() == "secure" for seg in rest)
    has_httponly = any(seg.lower() == "httponly" for seg in rest)

    samesite: Optional[str] = None
    for seg in rest:
        if seg.lower().startswith("samesite="):
            parts = seg.split("=", 1)
            if len(parts) > 1:
                samesite = parts[1].strip()
            break

    return {"name": name, "secure": has_secure, "httponly": has_httponly, "samesite": samesite, "raw": raw_header}


def score_cookie(parsed: Dict[str, Any], is_https: bool) -> Dict[str, Any]:
    """Score missing security flags on every cookie observed. Flags are
    reported regardless of whether the name looks session-like -- a real
    run had an admin-panel session cookie, CA_PIN_ADMIN, whose name
    matched none of the known session-name markers, so a name-gated
    version of this check reported `issues: []` for a cookie with
    neither Secure nor HttpOnly set."""
    issues: List[str] = []
    is_session = looks_like_session_cookie(parsed["name"])

    if not parsed["secure"]:
        issues.append("missing Secure flag")
    if not parsed["httponly"]:
        issues.append("missing HttpOnly flag")
    if parsed["samesite"] is None:
        issues.append("missing SameSite attribute")
    elif parsed["samesite"].lower() == "none" and not parsed["secure"]:
        issues.append("SameSite=None without Secure")

    res = dict(parsed)
    res["is_session_cookie"] = is_session
    res["issues"] = issues
    if not is_https:
        res["note"] = "served over a page not confirmed HTTPS -- Secure flag has reduced practical effect here"
    return res


def parse_cookies(set_cookie_lines: List[str], is_https: bool) -> List[Dict[str, Any]]:
    return [score_cookie(parse_cookie_line(line), is_https) for line in set_cookie_lines]


# ---------------------------------------------------------------- headers

ALL_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
)

HSTS_MIN_MAX_AGE = 31536000


def _csp_directives(value: str) -> Dict[str, List[str]]:
    """Split a CSP value into {directive-name (lowercased): [source tokens]}."""
    directives: Dict[str, List[str]] = {}
    for part in value.split(";"):
        tokens = part.split()
        if not tokens:
            continue
        name = tokens[0].lower()
        # First occurrence wins, per the CSP spec.
        directives.setdefault(name, tokens[1:])
    return directives


def _is_wildcard_source(tok: str) -> bool:
    """True for the bare "*" token or a host-position wildcard like
    "https://*.cdn.example.com" or "*.example.com". A path-only wildcard
    like "https://x.example/*" is NOT a wildcard source -- the host is
    still pinned to one exact origin, which is the actual security
    distinction CSP cares about here."""
    if tok == "*":
        return True
    rest = tok.split("://", 1)[1] if "://" in tok else tok
    authority = rest.split("/", 1)[0]
    return "*" in authority


def score_csp(value: str) -> List[str]:
    issues: List[str] = []
    directives = _csp_directives(value)
    all_tokens = [tok.lower() for toks in directives.values() for tok in toks]

    if "'unsafe-inline'" in all_tokens:
        issues.append("CSP contains 'unsafe-inline'")
    if "'unsafe-eval'" in all_tokens:
        issues.append("CSP contains 'unsafe-eval'")
    if any(_is_wildcard_source(tok) for tok in all_tokens):
        issues.append("CSP contains wildcard '*' source")
    if "data:" in all_tokens:
        issues.append("CSP contains 'data:' source")
    if "frame-ancestors" not in directives:
        issues.append("CSP omits frame-ancestors directive")
    if "object-src" not in directives:
        issues.append("CSP omits object-src directive")
    return issues


def score_hsts(value: str) -> List[str]:
    issues: List[str] = []
    tokens = [t.strip().lower() for t in value.split(";") if t.strip()]

    max_age: Optional[int] = None
    for tok in tokens:
        if tok.startswith("max-age="):
            raw = tok.split("=", 1)[1].strip().strip('"')
            try:
                max_age = int(raw)
            except ValueError:
                max_age = None
            break

    if max_age is None:
        issues.append("HSTS max-age missing or not an integer")
    elif max_age < HSTS_MIN_MAX_AGE:
        issues.append(f"HSTS max-age={max_age} below {HSTS_MIN_MAX_AGE}")

    if "includesubdomains" not in tokens:
        issues.append("HSTS missing includeSubDomains")
    return issues


def score_xcto(value: str) -> List[str]:
    if value.strip().lower() != "nosniff":
        return [f"X-Content-Type-Options value '{value.strip()}' is not 'nosniff'"]
    return []


def score_xfo(value: str) -> List[str]:
    if value.strip().upper() not in ("DENY", "SAMEORIGIN"):
        return [f"X-Frame-Options value '{value.strip()}' is not DENY or SAMEORIGIN"]
    return []


WEAKNESS_SCORERS = {
    "content-security-policy": score_csp,
    "strict-transport-security": score_hsts,
    "x-content-type-options": score_xcto,
    "x-frame-options": score_xfo,
}


def parse_headers(headers: Dict[str, str]) -> List[Dict[str, Any]]:
    """Return one entry per core header (always all six, in ALL_HEADERS order):
    {header, present, value, issues}. `headers` keys must be lowercased."""
    entries: List[Dict[str, Any]] = []
    for name in ALL_HEADERS:
        if name not in headers:
            entries.append({"header": name, "present": False, "value": None,
                            "issues": ["missing header"]})
            continue
        value = headers[name]
        scorer = WEAKNESS_SCORERS.get(name)
        issues = scorer(value) if scorer else []
        entries.append({"header": name, "present": True, "value": value, "issues": issues})
    return entries


# ---------------------------------------------------------------- SRI


class _AssetParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.raw_assets: List[Tuple[str, str, bool]] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        attrs_dict = {k.lower(): (v or "") for k, v in attrs if k}

        if tag.lower() == "script" and "src" in attrs_dict:
            src = attrs_dict["src"].strip()
            if src:
                self.raw_assets.append(("script", src, "integrity" in attrs_dict))

        elif tag.lower() == "link":
            rel = attrs_dict.get("rel", "").lower().split()
            if "stylesheet" in rel and "href" in attrs_dict:
                href = attrs_dict["href"].strip()
                if href:
                    self.raw_assets.append(("link", href, "integrity" in attrs_dict))


def is_cross_origin(asset_url: str, page_host: str) -> bool:
    """Return True if asset hostname differs from page hostname.

    A missing/None hostname (e.g. data: URI, relative anchor, or malformed URL)
    is treated as same-origin / not cross-origin.
    """
    if not page_host:
        return False

    try:
        parsed = urllib.parse.urlparse(asset_url)
        asset_host = parsed.hostname
    except Exception:
        return False

    if not asset_host:
        return False

    return asset_host.lower() != page_host.lower()


def parse_sri(body: str, final_url: str) -> Dict[str, Any]:
    """Parses <script src> / <link rel=stylesheet href> tags from `body`
    (resolving relative URLs against `final_url`) and scores cross-origin
    ones missing Subresource Integrity. Same-origin assets are not
    flagged -- SRI doesn't apply to resources you already control."""
    page_host = urllib.parse.urlparse(final_url or "").hostname or ""

    parser = _AssetParser()
    try:
        parser.feed(body)
    except Exception:
        pass  # best-effort on malformed HTML

    flagged: List[Dict[str, str]] = []
    same_origin_count = 0
    cross_origin_with_sri_count = 0

    for tag, raw_url, has_integrity in parser.raw_assets:
        abs_url = urllib.parse.urljoin(final_url or "", raw_url)
        if is_cross_origin(abs_url, page_host):
            if not has_integrity:
                flagged.append({"tag": tag, "url": abs_url})
            else:
                cross_origin_with_sri_count += 1
        else:
            same_origin_count += 1

    return {
        "total_assets_scanned": len(parser.raw_assets),
        "same_origin_assets_count": same_origin_count,
        "cross_origin_with_sri_count": cross_origin_with_sri_count,
        "cross_origin_missing_integrity_count": len(flagged),
        "cross_origin_missing_integrity": flagged,
    }


# ---------------------------------------------------------------- combined


def parse(raw: RawResponseAuditResult) -> Dict[str, Any]:
    """Combines cookie, header, and SRI audits derived from one fetched
    response. Only called on a successful fetch; the caller handles
    raw.error before getting here."""
    cookies = parse_cookies(raw.set_cookie_lines, raw.is_https)
    header_entries = parse_headers(raw.headers)
    sri = parse_sri(raw.body, raw.final_url or "")

    return {
        "final_url": raw.final_url,
        "is_https": raw.is_https,
        "cookies_found": len(cookies),
        "cookies": cookies,
        "headers_checked": len(header_entries),
        "missing_headers": [e["header"] for e in header_entries if not e["present"]],
        "weak_headers": [
            {"header": e["header"], "value": e["value"], "issues": e["issues"]}
            for e in header_entries if e["present"] and e["issues"]
        ],
        "headers": header_entries,
        "sri_total_assets_scanned": sri["total_assets_scanned"],
        "sri_same_origin_assets_count": sri["same_origin_assets_count"],
        "sri_cross_origin_with_sri_count": sri["cross_origin_with_sri_count"],
        "sri_cross_origin_missing_integrity_count": sri["cross_origin_missing_integrity_count"],
        "sri_cross_origin_missing_integrity": sri["cross_origin_missing_integrity"],
    }
