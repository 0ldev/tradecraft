"""
Unit tests for response_security_audit adapter (execution and parsing).
Merges the former cookie_security_check/security_header_check/sri_check
adapter test suites -- all real regression cases from those files are
preserved here unchanged.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from tradecraft.adapters.response_security_audit.execute import (
    RawResponseAuditResult,
    execute,
    normalize_target_url,
)
from tradecraft.adapters.response_security_audit.parse import (
    _AssetParser,
    is_cross_origin,
    looks_like_session_cookie,
    parse,
    parse_cookie_line,
    parse_headers,
    parse_sri,
    score_cookie,
    score_csp,
    score_hsts,
    score_xcto,
    score_xfo,
)

STRONG_HEADERS = {
    "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
    "content-security-policy": "default-src 'self'; object-src 'none'; frame-ancestors 'self'",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "geolocation=()",
}


def _by_name(entries):
    return {e["header"]: e for e in entries}


# ---------------------------------------------------------------- normalize_target_url


def test_normalize_target_url():
    assert normalize_target_url("examplepaint.com.br") == "https://examplepaint.com.br"
    assert normalize_target_url("http://example.com/login") == "http://example.com/login"
    assert normalize_target_url("https://example.com") == "https://example.com"
    assert normalize_target_url("") == ""


# ---------------------------------------------------------------- cookies


def test_looks_like_session_cookie():
    assert looks_like_session_cookie("PHPSESSID") is True
    assert looks_like_session_cookie("auth_token") is True
    assert looks_like_session_cookie("session") is True
    assert looks_like_session_cookie("laravel_session") is True
    assert looks_like_session_cookie("csrf_token") is True
    assert looks_like_session_cookie(".AspNetCore.Antiforgery.9TtSrW0hzOs") is True
    assert looks_like_session_cookie("remember_web_59ba36addc2b2f9401580f014c7f58e4e") is True
    assert looks_like_session_cookie("jwt") is True
    assert looks_like_session_cookie("tracking_pixel_id") is False
    assert looks_like_session_cookie("theme") is False


def test_parse_cookie_line_attributes():
    raw = "PHPSESSID=abc12345; path=/; domain=.target.com; Secure; HttpOnly; SameSite=Strict"
    res = parse_cookie_line(raw)
    assert res["name"] == "PHPSESSID"
    assert res["secure"] is True
    assert res["httponly"] is True
    assert res["samesite"] == "Strict"

    # Base64 with '=' inside value
    raw_b64 = "auth_token=dGVzdD09; path=/; HttpOnly"
    res_b64 = parse_cookie_line(raw_b64)
    assert res_b64["name"] == "auth_token"
    assert res_b64["secure"] is False
    assert res_b64["httponly"] is True
    assert res_b64["samesite"] is None


def test_score_cookie_session_missing_flags():
    parsed = {"name": "session_id", "secure": False, "httponly": True, "samesite": None, "raw": "session_id=123; HttpOnly"}
    scored = score_cookie(parsed, is_https=True)
    assert scored["is_session_cookie"] is True
    assert "missing Secure flag" in scored["issues"]
    assert "missing SameSite attribute" in scored["issues"]
    assert "missing HttpOnly flag" not in scored["issues"]


def test_score_cookie_flags_missing_attributes_on_non_session_named_cookie():
    # Real captured case (example.com admin panel): the session cookie
    # CA_PIN_ADMIN has neither Secure nor HttpOnly, but its name matches none
    # of looks_like_session_cookie's markers. A name-gated check reported
    # issues: [] for it; missing flags must be reported regardless of name.
    parsed = {
        "name": "CA_PIN_ADMIN", "secure": False, "httponly": False, "samesite": None,
        "raw": "CA_PIN_ADMIN=72d44eb724e137e973c0070633ee01d7; path=/",
    }
    scored = score_cookie(parsed, is_https=True)
    assert scored["is_session_cookie"] is False
    assert "missing Secure flag" in scored["issues"]
    assert "missing HttpOnly flag" in scored["issues"]
    assert "missing SameSite attribute" in scored["issues"]


def test_score_cookie_samesite_none_without_secure():
    parsed = {"name": "anon_token", "secure": False, "httponly": False, "samesite": "None", "raw": "anon_token=123; SameSite=None"}
    scored = score_cookie(parsed, is_https=True)
    assert "SameSite=None without Secure" in scored["issues"]


def test_score_cookie_http_note():
    parsed = {"name": "sess", "secure": True, "httponly": True, "samesite": "Lax", "raw": "sess=123; Secure; HttpOnly; SameSite=Lax"}
    scored = score_cookie(parsed, is_https=False)
    assert "not confirmed HTTPS" in scored["note"]


# ---------------------------------------------------------------- headers


def test_all_headers_present_and_strong_has_no_issues():
    entries = _by_name(parse_headers(dict(STRONG_HEADERS)))
    assert len(entries) == 6
    assert all(e["present"] for e in entries.values())
    assert all(e["issues"] == [] for e in entries.values())


@pytest.mark.parametrize("header", list(STRONG_HEADERS))
def test_each_header_missing_is_reported(header):
    headers = {k: v for k, v in STRONG_HEADERS.items() if k != header}
    entries = _by_name(parse_headers(headers))
    assert entries[header]["present"] is False
    assert entries[header]["value"] is None
    assert entries[header]["issues"] == ["missing header"]
    for other in STRONG_HEADERS:
        if other != header:
            assert entries[other]["present"] is True


def test_csp_unsafe_inline():
    issues = score_csp("default-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'none'")
    assert "CSP contains 'unsafe-inline'" in issues


def test_csp_unsafe_eval():
    issues = score_csp("script-src 'self' 'unsafe-eval'; object-src 'none'; frame-ancestors 'none'")
    assert "CSP contains 'unsafe-eval'" in issues


def test_csp_wildcard_source():
    issues = score_csp("script-src *; object-src 'none'; frame-ancestors 'none'")
    assert "CSP contains wildcard '*' source" in issues


def test_csp_host_wildcard_source():
    # A host-position wildcard (any subdomain) is the same risk class as a
    # bare "*" -- unlike a path-only wildcard, which pins the host.
    issues = score_csp("script-src https://*.cdn.example.com; object-src 'none'; frame-ancestors 'none'")
    assert "CSP contains wildcard '*' source" in issues

    issues = score_csp("script-src *.example.com; object-src 'none'; frame-ancestors 'none'")
    assert "CSP contains wildcard '*' source" in issues


def test_csp_data_source():
    issues = score_csp("img-src data:; object-src 'none'; frame-ancestors 'none'")
    assert "CSP contains 'data:' source" in issues


def test_csp_missing_frame_ancestors():
    issues = score_csp("default-src 'self'; object-src 'none'")
    assert issues == ["CSP omits frame-ancestors directive"]


def test_csp_missing_object_src():
    issues = score_csp("default-src 'self'; frame-ancestors 'self'")
    assert issues == ["CSP omits object-src directive"]


def test_csp_strong_has_no_issues():
    assert score_csp("default-src 'self'; object-src 'none'; frame-ancestors 'self'") == []


def test_csp_keyword_matching_is_token_exact():
    # 'unsafe-inline' appearing inside a nonce-free longer token must not trip the check
    assert score_csp("default-src 'self'; object-src 'none'; frame-ancestors 'self'; img-src https://x.example/*") == []


def test_hsts_max_age_too_low():
    assert score_hsts("max-age=3600; includeSubDomains") == ["HSTS max-age=3600 below 31536000"]


def test_hsts_max_age_exactly_threshold_is_ok():
    assert score_hsts("max-age=31536000; includeSubDomains") == []


def test_hsts_missing_include_subdomains():
    assert score_hsts("max-age=63072000") == ["HSTS missing includeSubDomains"]


def test_hsts_missing_max_age():
    assert score_hsts("includeSubDomains") == ["HSTS max-age missing or not an integer"]


def test_hsts_non_integer_max_age():
    assert score_hsts("max-age=abc; includeSubDomains") == ["HSTS max-age missing or not an integer"]


def test_hsts_include_subdomains_case_insensitive():
    assert score_hsts("max-age=63072000; includesubdomains") == []


def test_xcto_nosniff_ok():
    assert score_xcto("nosniff") == []


def test_xcto_other_value_weak():
    assert score_xcto("none") == ["X-Content-Type-Options value 'none' is not 'nosniff'"]


@pytest.mark.parametrize("value", ["DENY", "SAMEORIGIN", "deny"])
def test_xfo_allowed_values_ok(value):
    assert score_xfo(value) == []


def test_xfo_allow_from_is_weak():
    assert score_xfo("ALLOW-FROM https://a.example") == [
        "X-Frame-Options value 'ALLOW-FROM https://a.example' is not DENY or SAMEORIGIN"
    ]


@pytest.mark.parametrize("header", ["referrer-policy", "permissions-policy"])
def test_presence_only_headers_never_scored(header):
    headers = dict(STRONG_HEADERS)
    headers[header] = "totally-made-up-value; unsafe-inline * data:"
    entries = _by_name(parse_headers(headers))
    assert entries[header]["present"] is True
    assert entries[header]["issues"] == []


@pytest.mark.parametrize("header", ["referrer-policy", "permissions-policy"])
def test_presence_only_headers_missing_reported(header):
    headers = {k: v for k, v in STRONG_HEADERS.items() if k != header}
    entries = _by_name(parse_headers(headers))
    assert entries[header]["issues"] == ["missing header"]


def test_real_capture_github_com_headers():
    headers = {
        "strict-transport-security": "max-age=31536000; includeSubdomains; preload",
        "content-security-policy": (
            "default-src 'none'; base-uri 'self'; style-src 'unsafe-inline' github.githubassets.com; "
            "img-src 'self' data: blob: github.githubassets.com; frame-ancestors 'none'; "
            "upgrade-insecure-requests"
        ),
        "x-content-type-options": "nosniff",
        "x-frame-options": "deny",
        "referrer-policy": "origin-when-cross-origin, strict-origin-when-cross-origin",
    }
    entries = _by_name(parse_headers(headers))
    assert entries["strict-transport-security"]["issues"] == []
    assert entries["x-content-type-options"]["issues"] == []
    assert entries["x-frame-options"]["issues"] == []
    assert entries["referrer-policy"]["issues"] == []
    assert entries["permissions-policy"] == {
        "header": "permissions-policy", "present": False, "value": None, "issues": ["missing header"],
    }
    assert entries["content-security-policy"]["issues"] == [
        "CSP contains 'unsafe-inline'",
        "CSP contains 'data:' source",
        "CSP omits object-src directive",
    ]


# ---------------------------------------------------------------- SRI


def test_asset_parser_html_tags():
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <link rel="stylesheet" href="/css/local.css">
        <link rel="stylesheet" href="https://cdn.example.com/bootstrap.min.css" integrity="sha384-xyz">
        <link rel="stylesheet" href="https://cdn.example.com/font-awesome.css">
        <link rel="icon" href="/favicon.ico">
        <script src="https://cdn.example.com/jquery.min.js"></script>
        <script src="https://cdn.example.com/popper.js" integrity="sha256-abc"></script>
        <script>console.log("inline script without src");</script>
    </head>
    <body></body>
    </html>
    """
    parser = _AssetParser()
    parser.feed(html)

    assert len(parser.raw_assets) == 5
    assert parser.raw_assets[0] == ("link", "/css/local.css", False)
    assert parser.raw_assets[1] == ("link", "https://cdn.example.com/bootstrap.min.css", True)
    assert parser.raw_assets[2] == ("link", "https://cdn.example.com/font-awesome.css", False)
    assert parser.raw_assets[3] == ("script", "https://cdn.example.com/jquery.min.js", False)
    assert parser.raw_assets[4] == ("script", "https://cdn.example.com/popper.js", True)


def test_is_cross_origin():
    assert is_cross_origin("https://cdn.example.com/lib.js", "target.com") is True
    assert is_cross_origin("https://target.com/lib.js", "target.com") is False
    assert is_cross_origin("https://TARGET.com/lib.js", "target.com") is False
    assert is_cross_origin("/local/path/style.css", "target.com") is False
    assert is_cross_origin("data:text/javascript;base64,abc", "target.com") is False
    assert is_cross_origin("https://cdn.example.com/lib.js", "") is False


def test_parse_sri_relative_url_resolution():
    html = """
    <html>
    <head>
        <script src="app.js"></script>
        <script src="https://cdn.external.com/bundle.js"></script>
    </head>
    </html>
    """
    res = parse_sri(html, "https://target.com/subpath/index.html")
    assert res["total_assets_scanned"] == 2
    # Relative URL must be resolved against target.com/subpath/index.html,
    # and be same-origin (not flagged).
    assert res["same_origin_assets_count"] == 1
    assert res["cross_origin_missing_integrity_count"] == 1
    assert res["cross_origin_missing_integrity"][0]["url"] == "https://cdn.external.com/bundle.js"


def test_parse_sri_scoring():
    html = """
    <html><head>
    <script src="https://target.com/local.js"></script>
    <script src="https://cdn.example.com/with_sri.js" integrity="sha256-abc"></script>
    <script src="https://cdn.example.com/missing_sri.js"></script>
    <link rel="stylesheet" href="https://fonts.example.com/style.css">
    </head></html>
    """
    res = parse_sri(html, "https://target.com/")
    assert res["total_assets_scanned"] == 4
    assert res["same_origin_assets_count"] == 1
    assert res["cross_origin_with_sri_count"] == 1
    assert res["cross_origin_missing_integrity_count"] == 2
    assert len(res["cross_origin_missing_integrity"]) == 2
    assert res["cross_origin_missing_integrity"][0]["url"] == "https://cdn.example.com/missing_sri.js"
    assert res["cross_origin_missing_integrity"][1]["url"] == "https://fonts.example.com/style.css"


# ---------------------------------------------------------------- execute()


def _fake_response(headers=None, url="https://example.com/", history=None, cookie_lines=None, body=""):
    resp = MagicMock()
    resp.url = url
    resp.headers = headers if headers is not None else {}
    resp.history = history or []
    resp.text = body
    resp.raw.headers.getlist.return_value = cookie_lines or []
    return resp


def test_execute_empty_target_returns_error():
    raw = execute("   ")
    assert raw.error == "empty target URL"


def test_execute_request_exception_returns_error():
    import requests

    with patch(
        "tradecraft.adapters.response_security_audit.execute.requests.get",
        side_effect=requests.ConnectionError("connection refused"),
    ):
        raw = execute("https://unreachable.example")
    assert raw.error and "connection refused" in raw.error
    assert raw.headers == {}


def test_execute_unexpected_exception_returns_error():
    with patch(
        "tradecraft.adapters.response_security_audit.execute.requests.get",
        side_effect=ValueError("boom"),
    ):
        raw = execute("https://example.com")
    assert raw.error == "ValueError: boom"


def test_execute_lowercases_headers_from_final_response():
    from requests.structures import CaseInsensitiveDict

    resp = _fake_response(headers=CaseInsensitiveDict({"X-Frame-Options": "DENY", "Content-Type": "text/html"}))
    with patch("tradecraft.adapters.response_security_audit.execute.requests.get", return_value=resp) as get:
        raw = execute("example.com")
    assert raw.error is None
    assert raw.headers == {"x-frame-options": "DENY", "content-type": "text/html"}
    assert raw.is_https is True
    assert get.call_args.args[0] == "https://example.com"


def test_execute_collects_cookies_from_history_and_final_response():
    history_resp = MagicMock()
    history_resp.raw.headers.getlist.return_value = ["init_cookie=val1; path=/"]

    final_resp = _fake_response(
        url="https://example.com/dashboard",
        history=[history_resp],
        cookie_lines=["auth_session=secret123; path=/; Secure; HttpOnly; SameSite=Lax"],
    )

    with patch("tradecraft.adapters.response_security_audit.execute.requests.get", return_value=final_resp):
        res = execute("https://example.com/login")
        assert res.final_url == "https://example.com/dashboard"
        assert res.is_https is True
        assert len(res.set_cookie_lines) == 2
        assert "init_cookie" in res.set_cookie_lines[0]
        assert "auth_session" in res.set_cookie_lines[1]


def test_execute_body_is_capped():
    big_body = "x" * 10
    resp = _fake_response(body=big_body)
    with patch("tradecraft.adapters.response_security_audit.execute.requests.get", return_value=resp):
        raw = execute("https://example.com", max_body_bytes=5)
    assert raw.body == "xxxxx"


# ---------------------------------------------------------------- parse() (combined)


def test_parse_combines_all_three_checks():
    raw = RawResponseAuditResult(
        target="https://example.com",
        final_url="https://example.com/",
        is_https=True,
        headers={"x-content-type-options": "nosniff"},
        set_cookie_lines=["sid=1; HttpOnly", "theme=dark; path=/"],
        body='<script src="https://cdn.example.com/lib.js"></script>',
    )
    res = parse(raw)

    assert res["cookies_found"] == 2
    assert res["cookies"][0]["name"] == "sid"
    assert res["cookies"][0]["is_session_cookie"] is True
    assert "missing Secure flag" in res["cookies"][0]["issues"]

    assert res["headers_checked"] == 6
    assert "x-content-type-options" not in res["missing_headers"]

    assert res["sri_total_assets_scanned"] == 1
    assert res["sri_cross_origin_missing_integrity_count"] == 1
