"""
Unit tests for teamcity_auth_bypass_probe adapter and tool.
Mocks all network calls so tests run fully offline.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from tradecraft.adapters.teamcity_auth_bypass_probe.execute import (
    RawTeamCityResult,
    TeamCityProbeAttempt,
    execute,
    normalize_target_candidates,
)
from tradecraft.adapters.teamcity_auth_bypass_probe.parse import parse_teamcity_result
from tradecraft.tools.profiles import load_profile
from tradecraft.tools.registry import ALL_TOOLS
from tradecraft.tools.teamcity_auth_bypass_probe import TeamCityAuthBypassProbe


class TestTeamCityAuthBypassExecute:
    def test_normalize_target_candidates(self):
        c1 = normalize_target_candidates("ci.example.com")
        assert "https://ci.example.com" in c1
        assert "http://ci.example.com:8111" in c1

        c2 = normalize_target_candidates("https://ci.example.com:8111")
        assert c2 == ["https://ci.example.com:8111"]

        c3 = normalize_target_candidates("10.0.0.5", custom_port=9090)
        assert "https://10.0.0.5:9090" in c3
        assert "http://10.0.0.5:9090" in c3

    def test_execute_empty_target(self):
        res = execute("")
        assert res.error == "target is required"
        assert not res.attempts

    @patch("requests.Session")
    def test_execute_vulnerable_response(self, mock_session_cls):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        login_resp = MagicMock()
        login_resp.status_code = 200
        login_resp.text = "<html><title>Log in to TeamCity</title></html>"
        login_resp.headers = {"X-TeamCity-Node-Id": "MAIN"}

        # Probe /hax?jsp=/app/rest/server returns unauthenticated metadata
        bypass_resp = MagicMock()
        bypass_resp.status_code = 200
        bypass_resp.text = '{"version": "2023.11.3", "buildNumber": "147512", "versionMajor": 2023}'
        bypass_resp.json.return_value = {
            "version": "2023.11.3",
            "buildNumber": "147512",
            "versionMajor": 2023,
            "webUrl": "http://ci.test:8111",
        }

        mock_session.get.side_effect = [login_resp, bypass_resp]

        res = execute("https://vulnerable-ci.test:8111")
        assert res.teamcity_fingerprinted is True
        assert len(res.attempts) == 1
        assert res.attempts[0].is_vulnerable is True
        assert res.attempts[0].server_info.get("version") == "2023.11.3"

    @patch("requests.Session")
    def test_execute_safe_response(self, mock_session_cls):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        login_resp = MagicMock()
        login_resp.status_code = 200
        login_resp.text = "<html>TeamCity Log in</html>"
        login_resp.headers = {}

        safe_resp = MagicMock()
        safe_resp.status_code = 404
        safe_resp.text = "Not Found"
        safe_resp.json.side_effect = Exception("Not JSON")

        mock_session.get.side_effect = [login_resp, safe_resp, safe_resp, safe_resp]

        res = execute("https://safe-ci.test:8111")
        assert res.teamcity_fingerprinted is True
        assert len(res.attempts) == 3
        for a in res.attempts:
            assert a.is_vulnerable is False

    @patch("requests.Session")
    def test_execute_network_error(self, mock_session_cls):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        mock_session.get.side_effect = requests.exceptions.ConnectionError("Connection timed out")

        res = execute("https://offline-ci.test:8111")
        assert len(res.attempts) == 3
        for a in res.attempts:
            assert a.error is not None
            assert "timed out" in a.error


class TestTeamCityAuthBypassParse:
    def test_parse_vulnerable_result(self):
        raw = RawTeamCityResult(
            target="ci.example.com",
            base_url="https://ci.example.com:8111",
            teamcity_fingerprinted=True,
            attempts=[
                TeamCityProbeAttempt(
                    url="https://ci.example.com:8111/hax?jsp=/app/rest/server",
                    status_code=200,
                    is_vulnerable=True,
                    server_info={"version": "2023.11.3", "buildNumber": "147512"},
                )
            ],
        )
        parsed = parse_teamcity_result(raw)
        assert parsed["vulnerable"] is True
        assert parsed["status"] == "vulnerable"
        assert "CVE-2024-27198" in parsed["summary"]
        assert "2023.11.3" in parsed["summary"]
        assert "2023.11.4" in parsed["recommendation"]

    def test_parse_safe_result(self):
        raw = RawTeamCityResult(
            target="ci.example.com",
            base_url="https://ci.example.com:8111",
            teamcity_fingerprinted=True,
            attempts=[
                TeamCityProbeAttempt(
                    url="https://ci.example.com:8111/hax?jsp=/app/rest/server",
                    status_code=404,
                    is_vulnerable=False,
                )
            ],
        )
        parsed = parse_teamcity_result(raw)
        assert parsed["vulnerable"] is False
        assert parsed["status"] == "safe"
        assert "SAFE" in parsed["summary"]

    def test_parse_not_applicable(self):
        raw = RawTeamCityResult(
            target="web.example.com",
            base_url="https://web.example.com",
            teamcity_fingerprinted=False,
            attempts=[
                TeamCityProbeAttempt(url="https://web.example.com/hax?jsp=/app/rest/server", status_code=404),
            ],
        )
        parsed = parse_teamcity_result(raw)
        assert parsed["vulnerable"] is False
        assert parsed["status"] == "not_applicable"
        assert "NOT_APPLICABLE" in parsed["summary"]

    def test_parse_error(self):
        raw = RawTeamCityResult(target="ci.example.com", error="target is required")
        parsed = parse_teamcity_result(raw)
        assert parsed["vulnerable"] is False
        assert parsed["status"] == "error"
        assert parsed["error"] == "target is required"


class TestTeamCityAuthBypassTool:
    def test_registration(self):
        ids = [t.tool_id for t in ALL_TOOLS]
        assert "teamcity_auth_bypass_probe" in ids

    def test_spec_attributes(self):
        tool = TeamCityAuthBypassProbe()
        assert tool.spec.name == "teamcity_auth_bypass_probe"
        assert tool.required_binary is None
        assert tool.scope_param == "target"
        assert tool.destructive is False
        assert tool.is_available() is True
        assert "target" in tool.spec.parameters["properties"]

    @patch("tradecraft.adapters.teamcity_auth_bypass_probe.execute.execute")
    def test_tool_run(self, mock_exec):
        mock_exec.return_value = RawTeamCityResult(
            target="https://ci.example.com",
            attempts=[],
        )
        tool = TeamCityAuthBypassProbe()
        res = tool.run(target="https://ci.example.com")
        assert res["target"] == "https://ci.example.com"
        assert res["vulnerable"] is False

    def test_profile_membership(self):
        web = load_profile("web")
        cloud = load_profile("cloud")
        full = load_profile("full")
        assert "teamcity_auth_bypass_probe" in web
        assert "teamcity_auth_bypass_probe" in cloud
        assert "teamcity_auth_bypass_probe" in full
