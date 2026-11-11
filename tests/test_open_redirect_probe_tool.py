from unittest.mock import patch

from tradecraft.adapters.open_redirect_probe.execute import ParamAttempt, RawOpenRedirectResult
from tradecraft.tools.open_redirect_probe import OpenRedirectProbe
from tradecraft.tools.registry import ALL_TOOLS


def test_tool_identity_and_contract():
    tool = OpenRedirectProbe()
    assert tool.tool_id == "open_redirect_probe"
    assert tool.spec.name == "open_redirect_probe"
    assert tool.scope_param == "target"
    assert tool.destructive is False
    assert tool.required_binary is None
    assert any(t.tool_id == "open_redirect_probe" for t in ALL_TOOLS)


def test_run_forwards_params_and_returns_parsed_hit():
    tool = OpenRedirectProbe()
    raw = RawOpenRedirectResult(
        target="https://example.com/login?next=/x",
        tested_params=["next"],
        attempts=[ParamAttempt("next", "plain_https", "https://tradecraft-oob-canary.invalid/", 302,
                               "https://tradecraft-oob-canary.invalid/", True)],
    )
    with patch("tradecraft.adapters.open_redirect_probe.execute.execute", return_value=raw) as ex:
        out = tool.run(target="https://example.com/login?next=/x", param="next", timeout=5)
    ex.assert_called_once_with(target="https://example.com/login?next=/x", param="next", timeout=5)
    assert out["vulnerable_params"] == ["next"]


def test_run_error_is_reported():
    tool = OpenRedirectProbe()
    raw = RawOpenRedirectResult(target="https://example.com/login", error="target has no query parameters to test")
    with patch("tradecraft.adapters.open_redirect_probe.execute.execute", return_value=raw):
        out = tool.run(target="https://example.com/login")
    assert out == {"target": "https://example.com/login", "error": "target has no query parameters to test"}


def test_extract_facts_records_tested_or_vulnerable():
    tool = OpenRedirectProbe()
    # Error case -> empty
    assert tool.extract_facts({"target": "https://example.com/?next=/"}, {"error": "fail"}) == []
    assert tool.extract_facts({}, {}) == []

    clean = tool.extract_facts({"target": "https://example.com/login?next=/"}, {"reason": "no payload produced a redirect"})
    assert clean == [{"host": "example.com", "port": 443, "open_redirect_tested": True}]

    # Vulnerable
    vuln = tool.extract_facts(
        {"target": "https://example.com/login?next=/"},
        {"vulnerable_params": ["next"], "hits": [{"param": "next"}]},
    )
    assert vuln[0]["open_redirect_vulnerable"] is True
    assert "Open redirect confirmed" in vuln[0]["vulnerability"]
    assert vuln[0]["severity"] == "medium"
