"""
Unit tests for cyberpanel_rce_probe adapter and tool.
Mocks all network calls so tests run fully offline.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from tradecraft.adapters.cyberpanel_rce_probe.execute import (
    CyberPanelEndpointResult,
    RawCyberPanelResult,
    execute,
    normalize_target_candidates,
)
from tradecraft.adapters.cyberpanel_rce_probe.parse import parse_cyberpanel_result
from tradecraft.tools.cyberpanel_rce_probe import CyberPanelRceProbe
from tradecraft.tools.profiles import load_profile
from tradecraft.tools.registry import ALL_TOOLS


class TestCyberPanelRceExecute:
    def test_normalize_target_candidates(self):
        c1 = normalize_target_candidates("example.com")
        assert "https://example.com:8090" in c1
        assert "http://example.com:8090" in c1
        assert "https://example.com" in c1

        c2 = normalize_target_candidates("https://panel.example.com:8090")
        assert c2 == ["https://panel.example.com:8090"]

        c3 = normalize_target_candidates("10.0.0.5:8090")
        assert "https://10.0.0.5:8090" in c3
        assert "http://10.0.0.5:8090" in c3

    def test_execute_empty_target(self):
        res = execute("")
        assert res.error == "target is required"
        assert not res.probes

    @patch("requests.Session")
    def test_execute_vulnerable_response(self, mock_session_cls):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        get_resp = MagicMock()
        get_resp.status_code = 200
        get_resp.text = "<html><title>CyberPanel Login</title></html>"
        mock_session.get.return_value = get_resp
        mock_session.cookies.get.return_value = "mock_csrf_token_12345"

        # OPTIONS request returns RCE output
        rce_resp = MagicMock()
        rce_resp.status_code = 200
        rce_resp.text = '{"requestStatus": "uid=0(root) gid=0(root) tradecraft_probe_cve_2024_51567", "status": 1}'
        rce_resp.json.return_value = {
            "requestStatus": "uid=0(root) gid=0(root) tradecraft_probe_cve_2024_51567",
            "status": 1,
        }
        mock_session.request.return_value = rce_resp

        result = execute("https://vulnerable-panel.test:8090")
        assert result.target_identified_as_cyberpanel is True
        assert result.discovered_csrf_token == "mock_csrf_token_12345"
        assert len(result.probes) >= 1
        assert result.probes[0].is_vulnerable is True
        assert "uid=0(root)" in result.probes[0].output_snippet

    @patch("requests.Session")
    def test_execute_safe_response(self, mock_session_cls):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        get_resp = MagicMock()
        get_resp.status_code = 200
        get_resp.text = "<html>Welcome to CyberPanel</html>"
        mock_session.get.return_value = get_resp
        mock_session.cookies.get.return_value = "csrf_123"

        safe_resp = MagicMock()
        safe_resp.status_code = 405
        safe_resp.text = "Method Not Allowed"
        safe_resp.json.side_effect = Exception("Not JSON")
        mock_session.request.return_value = safe_resp

        result = execute("https://safe-panel.test:8090")
        assert result.target_identified_as_cyberpanel is True
        for p in result.probes:
            assert p.is_vulnerable is False

    @patch("requests.Session")
    def test_execute_network_error(self, mock_session_cls):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        mock_session.get.side_effect = requests.exceptions.ConnectionError("Connection refused")
        mock_session.request.side_effect = requests.exceptions.ConnectionError("Connection refused")

        result = execute("https://offline-panel.test:8090")
        assert len(result.probes) >= 1
        assert "Connection refused" in str(result.probes[0].error)


class TestCyberPanelRceParse:
    def test_parse_vulnerable_result(self):
        raw = RawCyberPanelResult(
            target="https://panel.test:8090",
            target_identified_as_cyberpanel=True,
            discovered_csrf_token="token_abc",
            probes=[
                CyberPanelEndpointResult(
                    base_url="https://panel.test:8090",
                    endpoint="/ftp/getresetstatus",
                    method="OPTIONS",
                    status_code=200,
                    output_snippet="uid=0(root) gid=0(root) tradecraft_probe_cve_2024_51567",
                    is_vulnerable=True,
                )
            ],
        )
        parsed = parse_cyberpanel_result(raw)
        assert parsed["vulnerable"] is True
        assert parsed["status"] == "vulnerable"
        assert "CVE-2024-51567" in parsed["summary"]
        assert "uid=0(root)" in parsed["execution_proof"]
        assert parsed["endpoint"] == "/ftp/getresetstatus"
        assert "2.3.7" in parsed["recommendation"]

    def test_parse_safe_result(self):
        raw = RawCyberPanelResult(
            target="https://panel.test:8090",
            target_identified_as_cyberpanel=True,
            probes=[
                CyberPanelEndpointResult(
                    base_url="https://panel.test:8090",
                    endpoint="/ftp/getresetstatus",
                    method="OPTIONS",
                    status_code=405,
                    output_snippet="Method Not Allowed",
                    is_vulnerable=False,
                )
            ],
        )
        parsed = parse_cyberpanel_result(raw)
        assert parsed["vulnerable"] is False
        assert parsed["status"] == "safe"
        assert "SAFE" in parsed["summary"]

    def test_parse_not_applicable(self):
        raw = RawCyberPanelResult(
            target="https://other.test",
            target_identified_as_cyberpanel=False,
            probes=[
                CyberPanelEndpointResult(
                    base_url="https://other.test:8090",
                    endpoint="/ftp/getresetstatus",
                    method="OPTIONS",
                    status_code=404,
                    is_vulnerable=False,
                )
            ],
        )
        parsed = parse_cyberpanel_result(raw)
        assert parsed["vulnerable"] is False
        assert parsed["status"] == "not_applicable"
        assert "NOT_APPLICABLE" in parsed["summary"]

    def test_parse_error(self):
        raw = RawCyberPanelResult(target="https://panel.test", error="target is required")
        parsed = parse_cyberpanel_result(raw)
        assert parsed["vulnerable"] is False
        assert parsed["status"] == "error"
        assert parsed["error"] == "target is required"


class TestCyberPanelRceTool:
    def test_registration(self):
        ids = [t.tool_id for t in ALL_TOOLS]
        assert "cyberpanel_rce_probe" in ids

    def test_spec_attributes(self):
        tool = CyberPanelRceProbe()
        assert tool.spec.name == "cyberpanel_rce_probe"
        assert tool.required_binary is None
        assert tool.scope_param == "target"
        assert tool.destructive is False
        assert tool.is_available() is True
        assert "target" in tool.spec.parameters["properties"]

    @patch("tradecraft.adapters.cyberpanel_rce_probe.execute.execute")
    def test_tool_run(self, mock_exec):
        mock_exec.return_value = RawCyberPanelResult(
            target="https://panel.test:8090",
            probes=[],
        )
        tool = CyberPanelRceProbe()
        res = tool.run(target="https://panel.test:8090")
        assert res["target"] == "https://panel.test:8090"
        assert res["vulnerable"] is False

    def test_profile_membership(self):
        web = load_profile("web")
        full = load_profile("full")
        assert "cyberpanel_rce_probe" in web
        assert "cyberpanel_rce_probe" in full
