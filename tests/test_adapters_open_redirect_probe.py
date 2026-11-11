import urllib.parse
from unittest.mock import patch

import requests

from tradecraft.adapters.open_redirect_probe.execute import (
    CANARY_HOST,
    PAYLOAD_TEMPLATES,
    REDIRECT_PARAM_NAMES,
    ParamAttempt,
    RawOpenRedirectResult,
    execute,
)
from tradecraft.adapters.open_redirect_probe.parse import parse_open_redirect_result

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tradecraft/1.0"}


class FakeResp:
    def __init__(self, status, location=""):
        self.status_code = status
        self.headers = {"Location": location} if location else {}
        self.content = b""


def _recorder(responder, calls):
    def fake_get(url, headers=None, timeout=None, verify=None, allow_redirects=None):
        calls.append({
            "url": url,
            "headers": dict(headers or {}),
            "timeout": timeout,
            "verify": verify,
            "allow_redirects": allow_redirects,
        })
        out = responder(url)
        if isinstance(out, Exception):
            raise out
        return out
    return fake_get


def _safe_responder(url):
    return FakeResp(302, "/dashboard")


# --- payload + request construction ----------------------------------------

def test_payload_table_has_ten_entries_with_canary():
    assert len(PAYLOAD_TEMPLATES) == 10
    assert CANARY_HOST == "tradecraft-oob-canary.invalid"


def test_exact_request_urls_for_single_param():
    calls = []
    with patch(
        "tradecraft.adapters.open_redirect_probe.execute.requests.get",
        side_effect=_recorder(_safe_responder, calls),
    ):
        raw = execute("https://example.com/login?next=/dashboard&lang=en", param="next", timeout=7)

    assert raw.error is None
    assert raw.tested_params == ["next"]
    assert len(calls) == 10
    assert calls[0]["url"] == (
        "https://example.com/login?next=https%3A%2F%2Ftradecraft-oob-canary.invalid%2F&lang=en"
    )
    assert calls[0]["headers"] == UA
    assert calls[0]["timeout"] == 7
    assert calls[0]["verify"] is False
    assert calls[0]["allow_redirects"] is False

    # Userinfo trick uses the target's own hostname.
    userinfo = next(c for c in calls if "%40" in c["url"])
    assert urllib.parse.unquote(userinfo["url"]) == (
        "https://example.com/login?next=https://example.com@tradecraft-oob-canary.invalid/&lang=en"
    )
    urls = [urllib.parse.unquote_plus(c["url"]) for c in calls]
    assert "https://example.com/login?next=//tradecraft-oob-canary.invalid/&lang=en" in urls
    assert "https://example.com/login?next=///tradecraft-oob-canary.invalid/&lang=en" in urls
    assert "https://example.com/login?next=https:tradecraft-oob-canary.invalid&lang=en" in urls


def test_default_param_selection_prefers_redirect_names():
    calls = []
    target = "https://example.com/go?lang=en&next=/home&utm_source=x"
    with patch(
        "tradecraft.adapters.open_redirect_probe.execute.requests.get",
        side_effect=_recorder(_safe_responder, calls),
    ):
        raw = execute(target)
    assert raw.tested_params == ["next"]
    assert {urllib.parse.parse_qs(urllib.parse.urlsplit(c["url"]).query)["lang"][0] for c in calls} == {"en"}
    assert all("utm_source=x" in c["url"] for c in calls)


def test_default_param_selection_falls_back_to_all_params():
    calls = []
    with patch(
        "tradecraft.adapters.open_redirect_probe.execute.requests.get",
        side_effect=_recorder(_safe_responder, calls),
    ):
        raw = execute("https://example.com/search?q=shoes&page=2")
    assert raw.tested_params == ["q", "page"]
    assert len(calls) == 20


def test_redirect_param_names_are_lowercase_and_include_core_names():
    assert {"next", "redirect", "return_url", "callbackurl"} <= REDIRECT_PARAM_NAMES
    assert all(n == n.lower() for n in REDIRECT_PARAM_NAMES)


def test_no_query_params_is_error_without_requests():
    with patch("tradecraft.adapters.open_redirect_probe.execute.requests.get") as get:
        raw = execute("https://example.com/login")
    assert raw.error == "target has no query parameters to test"
    get.assert_not_called()


def test_unknown_explicit_param_is_error_without_requests():
    with patch("tradecraft.adapters.open_redirect_probe.execute.requests.get") as get:
        raw = execute("https://example.com/login?next=/x", param="return")
    assert raw.error == "'return' is not a query parameter on target"
    get.assert_not_called()


def test_request_exception_is_isolated_per_attempt():
    def responder(url):
        if "next=%2F%2Ftradecraft-oob-canary.invalid%2F" in url:
            return requests.ConnectionError("reset by peer")
        return FakeResp(302, "/home")

    calls = []
    with patch(
        "tradecraft.adapters.open_redirect_probe.execute.requests.get",
        side_effect=_recorder(responder, calls),
    ):
        raw = execute("https://example.com/login?next=/x", param="next")
    assert len(calls) == 10
    errored = [a for a in raw.attempts if a.error]
    assert len(errored) == 1
    assert errored[0].payload_label == "protocol_relative"
    assert "reset by peer" in errored[0].error


# --- parse.py ----------------------------------------------------------------

def _raw(attempts, tested=("next",), target="https://example.com/login?next=/x"):
    return RawOpenRedirectResult(target=target, tested_params=list(tested), attempts=attempts)


def test_parse_reports_real_canary_redirect():
    raw = _raw([
        ParamAttempt("next", "plain_https", "https://tradecraft-oob-canary.invalid/", 302,
                     "https://tradecraft-oob-canary.invalid/", True),
        ParamAttempt("next", "protocol_relative", "//tradecraft-oob-canary.invalid/", 302, "/home", False),
    ])
    out = parse_open_redirect_result(raw)
    assert out["vulnerable_params"] == ["next"]
    assert out["tested_params"] == ["next"]
    assert out["hits"] == [{
        "param": "next",
        "payload_label": "plain_https",
        "payload": "https://tradecraft-oob-canary.invalid/",
        "status": 302,
        "location": "https://tradecraft-oob-canary.invalid/",
    }]


def test_substring_mention_in_location_is_not_a_hit():
    calls = []
    def responder(url):
        return FakeResp(302, "https://example.com/login?next=https://tradecraft-oob-canary.invalid/")
    with patch(
        "tradecraft.adapters.open_redirect_probe.execute.requests.get",
        side_effect=_recorder(responder, calls),
    ):
        raw = execute("https://example.com/login?next=/x", param="next")
    out = parse_open_redirect_result(raw)
    assert "vulnerable_params" not in out
    assert out["reason"] == "no payload produced a redirect to the canary host across 1 parameter(s) tested"


def test_userinfo_location_to_canary_is_a_hit():
    calls = []
    def responder(url):
        if "example.com%40tradecraft-oob-canary.invalid" in url:
            return FakeResp(302, "https://example.com@tradecraft-oob-canary.invalid/")
        return FakeResp(302, "/home")
    with patch(
        "tradecraft.adapters.open_redirect_probe.execute.requests.get",
        side_effect=_recorder(responder, calls),
    ):
        raw = execute("https://example.com/login?next=/x", param="next")
    hits = [a for a in raw.attempts if a.redirects_to_canary]
    assert [a.payload_label for a in hits] == ["userinfo_trick"]


def test_parse_no_hits_reason_and_error_passthrough():
    out = parse_open_redirect_result(_raw([ParamAttempt("next", "plain_https", "x", 200, "", False)], tested=("next", "r")))
    assert out == {
        "target": "https://example.com/login?next=/x",
        "reason": "no payload produced a redirect to the canary host across 2 parameter(s) tested",
    }
    err = parse_open_redirect_result(RawOpenRedirectResult(target="t", error="boom"))
    assert err == {"target": "t", "error": "boom"}


def test_parse_vulnerable_params_are_sorted_unique():
    raw = _raw([
        ParamAttempt("return", "plain_https", "p", 302, "https://tradecraft-oob-canary.invalid/", True),
        ParamAttempt("next", "plain_https", "p", 302, "https://tradecraft-oob-canary.invalid/", True),
        ParamAttempt("next", "no_trailing_slash", "p", 301, "https://tradecraft-oob-canary.invalid", True),
    ], tested=("return", "next"))
    out = parse_open_redirect_result(raw)
    assert out["vulnerable_params"] == ["next", "return"]
    assert len(out["hits"]) == 3


def test_blank_redirect_param_is_still_tested():
    with patch("tradecraft.adapters.open_redirect_probe.execute.requests.get") as get:
        get.return_value = FakeResp(302, "https://somewhere.example/")
        raw = execute("https://example.com/login?next=&x=1")
    assert raw.tested_params == ["next"]
    sent = [c.args[0] for c in get.call_args_list]
    assert sent, "blank redirect parameter must produce requests"
    assert all("x=1" in u for u in sent)
