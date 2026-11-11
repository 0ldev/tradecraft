"""Unit tests for the websocket_security_probe tool layer."""
from __future__ import annotations

from unittest.mock import patch

from tradecraft.adapters.websocket_security_probe.execute import RawWebsocketProbeRun
from tradecraft.tools.websocket_security_probe import WebsocketSecurityProbe


def test_tool_attributes():
    tool = WebsocketSecurityProbe()
    assert tool.tool_id == "websocket_security_probe"
    assert tool.scope_param == "target"
    assert tool.destructive is False


def test_run_error_is_reported():
    tool = WebsocketSecurityProbe()
    failed = RawWebsocketProbeRun(target="", error="invalid target: ''")
    with patch("tradecraft.tools.websocket_security_probe.wsp_execute.execute", return_value=failed):
        result = tool.run(target="")
    assert result == {"target": "", "error": "invalid target: ''"}


def test_extract_facts_only_when_vulnerable():
    tool = WebsocketSecurityProbe()
    params = {"target": "chat.example.com:443"}
    vulnerable_result = {
        "target": "chat.example.com:443",
        "host": "chat.example.com",
        "port": 443,
        "vulnerable": True,
        "cross_origin_accepted": ["https://evil.tradecraft-probe.test"],
    }
    facts = tool.extract_facts(params, dict(vulnerable_result))
    assert len(facts) == 1
    assert facts[0]["host"] == "chat.example.com"
    assert facts[0]["severity"] == "high"

    clean_result = {"target": "chat.example.com:443", "host": "chat.example.com", "port": 443, "vulnerable": False, "cross_origin_accepted": []}
    assert tool.extract_facts(params, clean_result) == []
