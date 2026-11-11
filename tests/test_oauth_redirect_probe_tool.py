"""Unit tests for the oauth_redirect_probe tool layer."""
from __future__ import annotations

from unittest.mock import patch

from tradecraft.adapters.oauth_redirect_probe.execute import RawOauthRedirectResult
from tradecraft.tools.oauth_redirect_probe import OauthRedirectProbe


def test_tool_attributes():
    tool = OauthRedirectProbe()
    assert tool.tool_id == "oauth_redirect_probe"
    assert tool.scope_param == "target"
    assert tool.destructive is False


def test_run_error_is_reported():
    tool = OauthRedirectProbe()
    failed = RawOauthRedirectResult(target="https://idp.example.com/oauth/authorize", error="no redirect_uri")
    with patch("tradecraft.tools.oauth_redirect_probe.orp_execute.execute", return_value=failed):
        result = tool.run(target="https://idp.example.com/oauth/authorize")
    assert result == {"target": "https://idp.example.com/oauth/authorize", "error": "no redirect_uri"}


def test_extract_facts_only_when_vulnerable():
    tool = OauthRedirectProbe()
    params = {"target": "https://idp.example.com/oauth/authorize?redirect_uri=x"}
    vulnerable_result = {
        "target": "https://idp.example.com/oauth/authorize?redirect_uri=x",
        "vulnerable": True,
        "accepted_techniques": ["subdomain_trick"],
    }
    facts = tool.extract_facts(params, dict(vulnerable_result))
    assert len(facts) == 1
    assert facts[0]["host"] == "idp.example.com"
    assert facts[0]["severity"] == "high"

    clean_result = {"target": "https://idp.example.com", "vulnerable": False, "accepted_techniques": []}
    assert tool.extract_facts(params, clean_result) == []
