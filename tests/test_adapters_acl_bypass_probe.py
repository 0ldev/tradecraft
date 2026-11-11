from unittest.mock import patch

import requests

from tradecraft.adapters.acl_bypass_probe.execute import (
    RawAclBypassResult,
    VariantAttempt,
    _build_path_variants,
    execute,
    normalize_target_url,
)
from tradecraft.adapters.acl_bypass_probe.parse import parse_acl_bypass_result

FORBIDDEN_HTML = b"""<html>
<head><title>403 Forbidden</title></head>
<body>
<center><h1>403 Forbidden</h1></center>
<hr><center>nginx/1.24.0</center>
</body>
</html>
"""

ADMIN_JSON = b'{"user":"admin","roles":["ADMIN"],"panels":["users","billing","audit"],"generated":"2026-11-05T09:12:44Z"}'


class FakeResp:
    def __init__(self, status, body):
        self.status_code = status
        self.content = body


def _fake_get_factory(rules, default=(403, FORBIDDEN_HTML), calls=None):
    """rules: callable(url, headers) -> (status, body) or raises."""
    def fake_get(url, headers=None, timeout=None, verify=None, allow_redirects=None):
        if calls is not None:
            calls.append({
                "url": url,
                "headers": dict(headers or {}),
                "timeout": timeout,
                "verify": verify,
                "allow_redirects": allow_redirects,
            })
        out = rules(url, headers or {})
        if isinstance(out, Exception):
            raise out
        status, body = out
        return FakeResp(status, body)
    return fake_get


UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tradecraft/1.0"}


# --- normalization / variant construction ------------------------------------

def test_normalize_target_url():
    assert normalize_target_url("example.com/admin") == "https://example.com/admin"
    assert normalize_target_url("http://example.com/admin") == "http://example.com/admin"
    assert normalize_target_url("  ") == ""


def test_path_variant_table_single_segment_skips_encoded_rows():
    labels = [label for label, _ in _build_path_variants("/admin")]
    assert "encoded_slash_prefix" not in labels
    assert "double_encoded_slash" not in labels
    assert len(labels) == 16  # 16 rows before dedup; dedup happens in execute()


def test_path_variant_encoded_slash_rows_for_multi_segment():
    variants = dict(_build_path_variants("/api/admin"))
    assert variants["encoded_slash_prefix"] == "/api%2fadmin"
    assert variants["double_encoded_slash"] == "/api%252fadmin"


# --- execute: exact URLs, headers, and bodies --------------------------------

def test_execute_sends_exact_requests_for_admin_path():
    calls = []
    fake = _fake_get_factory(lambda u, h: (403, FORBIDDEN_HTML), calls=calls)
    with patch("tradecraft.adapters.acl_bypass_probe.execute.requests.get", side_effect=fake):
        raw = execute("https://example.com/admin")

    assert raw.error is None
    assert raw.baseline_status == 403
    assert raw.baseline_was_blocked is True
    assert raw.baseline_length == len(FORBIDDEN_HTML)

    # Baseline first, no extra headers beyond User-Agent.
    base = calls[0]
    assert base["url"] == "https://example.com/admin"
    assert base["headers"] == UA
    assert base["timeout"] == 10
    assert base["verify"] is False
    assert base["allow_redirects"] is False

    urls = [c["url"] for c in calls[1:]]
    assert urls[:15] == [
        "https://example.com/admin/",
        "https://example.com/admin/.",
        "https://example.com/admin//",
        "https://example.com/admin/./",
        "https://example.com/admin/..;/",
        "https://example.com/admin%20",
        "https://example.com/admin%09",
        "https://example.com/admin?",
        "https://example.com/admin#",
        "https://example.com/admin;",
        "https://example.com/ADMIN",
        "https://example.com/.admin",
        "https://example.com//admin",
        "https://example.com/./admin",
        "https://example.com/..;/admin",
    ]
    # 15 path attempts (swapcase duplicates uppercase for '/admin' and is skipped)
    # plus 14 header attempts, plus the baseline request.
    assert len(calls) == 1 + 15 + 14
    assert len(raw.attempts) == 29


def test_execute_header_variants_use_original_url_and_one_extra_header():
    calls = []
    fake = _fake_get_factory(lambda u, h: (403, FORBIDDEN_HTML), calls=calls)
    with patch("tradecraft.adapters.acl_bypass_probe.execute.requests.get", side_effect=fake):
        raw = execute("https://example.com/api/admin?x=1")

    header_calls = [c for c in calls if c["headers"] != UA]
    assert len(header_calls) == 14
    for c in header_calls:
        assert c["url"] == "https://example.com/api/admin?x=1"
        assert len(c["headers"]) == 2
    assert header_calls[0]["headers"] == {**UA, "X-Original-URL": "/api/admin"}
    assert header_calls[1]["headers"] == {**UA, "X-Rewrite-URL": "/api/admin"}
    assert header_calls[2]["headers"] == {**UA, "X-Forwarded-For": "127.0.0.1"}
    assert header_calls[4]["headers"] == {**UA, "X-Forwarded-Host": "localhost"}
    assert header_calls[10]["headers"] == {**UA, "Forwarded": "for=127.0.0.1"}
    assert header_calls[13]["headers"] == {**UA, "X-Custom-IP-Authorization": "127.0.0.1"}


def test_execute_path_variant_keeps_query_string():
    calls = []
    fake = _fake_get_factory(lambda u, h: (403, FORBIDDEN_HTML), calls=calls)
    with patch("tradecraft.adapters.acl_bypass_probe.execute.requests.get", side_effect=fake):
        execute("https://example.com/api/admin?x=1")
    assert "https://example.com/api/admin/?x=1" in [c["url"] for c in calls]
    assert "https://example.com/api//admin?x=1" not in [c["url"] for c in calls]
    assert "https://example.com//api/admin?x=1" in [c["url"] for c in calls]


def test_execute_isolates_per_attempt_request_exception():
    def rules(url, headers):
        if headers.get("X-Forwarded-For") == "127.0.0.1":
            return requests.ConnectionError("connection reset")
        return (403, FORBIDDEN_HTML)

    fake = _fake_get_factory(rules)
    with patch("tradecraft.adapters.acl_bypass_probe.execute.requests.get", side_effect=fake):
        raw = execute("https://example.com/admin")

    errored = [a for a in raw.attempts if a.error]
    assert [a.label for a in errored] == ["x_forwarded_for_localhost"]
    assert "connection reset" in errored[0].error
    assert len(raw.attempts) == 29


def test_execute_baseline_exception_returns_error():
    fake = _fake_get_factory(lambda u, h: requests.Timeout("read timed out"))
    with patch("tradecraft.adapters.acl_bypass_probe.execute.requests.get", side_effect=fake):
        raw = execute("https://example.com/admin")
    assert raw.error == "read timed out"
    assert raw.attempts == []


def test_execute_still_runs_variants_when_baseline_not_blocked():
    calls = []
    fake = _fake_get_factory(lambda u, h: (200, ADMIN_JSON), calls=calls)
    with patch("tradecraft.adapters.acl_bypass_probe.execute.requests.get", side_effect=fake):
        raw = execute("https://example.com/admin")
    assert raw.baseline_status == 200
    assert raw.baseline_was_blocked is False
    assert len(calls) == 1 + 29


# --- parse.py -----------------------------------------------------------------

def _raw(baseline_status=403, baseline_length=len(FORBIDDEN_HTML), attempts=None, error=None):
    return RawAclBypassResult(
        target="https://example.com/admin",
        baseline_status=baseline_status,
        baseline_length=baseline_length,
        baseline_was_blocked=baseline_status in (401, 403),
        attempts=attempts or [],
        error=error,
    )


def test_parse_reports_flipped_variant_with_header_formatting():
    raw = _raw(attempts=[
        VariantAttempt("trailing_slash", "https://example.com/admin/", None, 403, len(FORBIDDEN_HTML)),
        VariantAttempt(
            "x_forwarded_for_localhost", "https://example.com/admin",
            ("X-Forwarded-For", "127.0.0.1"), 200, len(ADMIN_JSON),
        ),
    ])
    out = parse_acl_bypass_result(raw)
    assert out["target"] == "https://example.com/admin"
    assert out["baseline_status"] == 403
    assert out["baseline_length"] == len(FORBIDDEN_HTML)
    assert out["bypasses"] == [{
        "label": "x_forwarded_for_localhost",
        "url_or_header": "X-Forwarded-For: 127.0.0.1",
        "status": 200,
        "body_length": len(ADMIN_JSON),
    }]
    assert "truncated" not in out


def test_parse_reports_path_variant_by_url():
    raw = _raw(attempts=[
        VariantAttempt("semicolon_bypass", "https://example.com/admin/..;/", None, 200, 900),
    ])
    out = parse_acl_bypass_result(raw)
    assert out["bypasses"][0]["url_or_header"] == "https://example.com/admin/..;/"


def test_parse_ignores_same_length_or_still_blocked_or_errored():
    raw = _raw(attempts=[
        # Status flipped but body identical to the blocked page: generic error page.
        VariantAttempt("uppercase", "https://example.com/ADMIN", None, 200, len(FORBIDDEN_HTML)),
        # Still blocked.
        VariantAttempt("dot_slash", "https://example.com/admin/./", None, 401, 50),
        # Failed request.
        VariantAttempt("trailing_hash", "https://example.com/admin#", None, None, None, error="boom"),
    ])
    out = parse_acl_bypass_result(raw)
    assert out == {
        "target": "https://example.com/admin",
        "baseline_status": 403,
        "reason": "no variant bypassed the block",
    }


def test_parse_baseline_not_blocked_reports_reason():
    raw = _raw(baseline_status=200, baseline_length=10)
    out = parse_acl_bypass_result(raw)
    assert out == {
        "target": "https://example.com/admin",
        "baseline_status": 200,
        "reason": "baseline was not 401/403 (200); nothing to bypass",
    }


def test_parse_error_passthrough():
    raw = RawAclBypassResult(target="https://example.com/admin", error="dns failure")
    assert parse_acl_bypass_result(raw) == {"target": "https://example.com/admin", "error": "dns failure"}


def test_parse_caps_bypasses_at_ten_with_truncated_flag():
    attempts = [
        VariantAttempt(f"v{i}", f"https://example.com/admin/{i}", None, 200, 5000 + i)
        for i in range(12)
    ]
    out = parse_acl_bypass_result(_raw(attempts=attempts))
    assert len(out["bypasses"]) == 10
    assert out["truncated"] is True
