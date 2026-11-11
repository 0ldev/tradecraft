"""
Unit tests for ilias_rce_probe adapter and tool.
Mocks all network calls so tests run fully offline.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from tradecraft.adapters.ilias_rce_probe.execute import (
    RawIliasResult,
    execute,
    normalize_target_url,
)
from tradecraft.adapters.ilias_rce_probe.parse import parse_ilias_result
from tradecraft.tools.ilias_rce_probe import IliasRceProbe
from tradecraft.tools.profiles import load_profile
from tradecraft.tools.registry import ALL_TOOLS


class TestIliasRceExecute:
    def test_normalize_target_url(self):
        assert normalize_target_url("ilias.corp.com") == "https://ilias.corp.com"
        assert normalize_target_url("http://lms.test/") == "http://lms.test"
        assert normalize_target_url("  https://elearning.local/site  ") == "https://elearning.local/site"

    def test_execute_empty_target(self):
        res = execute("")
        assert res.error == "target is required"
        assert not res.shib_logout_responsive

    @patch("requests.Session")
    def test_execute_vulnerable_response(self, mock_session_cls):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        home_resp = MagicMock()
        home_resp.status_code = 200
        home_resp.text = "<html>Welcome to ILIAS e-Learning</html>"
        home_resp.headers = {}
        mock_session.get.return_value = home_resp

        # /ltiauth.php responds 200/302
        lti_resp = MagicMock()
        lti_resp.status_code = 200

        # /shib_logout.php responds with SOAP LogoutNotificationResponse
        shib_resp = MagicMock()
        shib_resp.status_code = 200
        shib_resp.text = (
            "<SOAP-ENV:Envelope><SOAP-ENV:Body>"
            "<ns1:LogoutNotificationResponse><OK/></ns1:LogoutNotificationResponse>"
            "</SOAP-ENV:Body></SOAP-ENV:Envelope>"
        )

        mock_session.post.side_effect = [lti_resp, shib_resp]

        res = execute("https://vulnerable-ilias.test")
        assert res.ilias_fingerprinted is True
        assert res.ltiauth_accessible is True
        assert res.shib_logout_responsive is True
        assert "<OK/>" in res.shib_response_snippet

    @patch("requests.Session")
    def test_execute_safe_response(self, mock_session_cls):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        home_resp = MagicMock()
        home_resp.status_code = 200
        home_resp.text = "<html>Generic CMS</html>"
        home_resp.headers = {}
        mock_session.get.return_value = home_resp

        safe_resp = MagicMock()
        safe_resp.status_code = 404
        safe_resp.text = "Not Found"
        mock_session.post.side_effect = [safe_resp, safe_resp]

        res = execute("https://safe-ilias.test")
        assert res.ltiauth_accessible is False
        assert res.shib_logout_responsive is False

    @patch("requests.Session")
    def test_execute_custom_host_header(self, mock_session_cls):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        home_resp = MagicMock()
        home_resp.status_code = 200
        home_resp.text = "ILIAS"
        home_resp.headers = {}
        mock_session.get.return_value = home_resp

        lti_resp = MagicMock(status_code=404)
        shib_resp = MagicMock(status_code=404, text="")
        mock_session.post.side_effect = [lti_resp, shib_resp]

        res = execute("https://10.0.0.5", host_header="lms.example.com")
        assert res.base_url == "https://10.0.0.5"

    @patch("requests.Session")
    def test_execute_network_error(self, mock_session_cls):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        mock_session.get.side_effect = requests.exceptions.ConnectionError("Connection timed out")
        mock_session.post.side_effect = requests.exceptions.ConnectionError("Connection timed out")

        res = execute("https://offline-target.test")
        assert res.error is not None
        assert "timed out" in res.error


class TestIliasRceParse:
    def test_parse_vulnerable_result(self):
        raw = RawIliasResult(
            target="https://lms.test",
            base_url="https://lms.test",
            ltiauth_status=200,
            ltiauth_accessible=True,
            shib_logout_status=200,
            shib_logout_responsive=True,
            shib_response_snippet="<LogoutNotificationResponse><OK/></LogoutNotificationResponse>",
            ilias_fingerprinted=True,
        )
        parsed = parse_ilias_result(raw)
        assert parsed["vulnerable"] is True
        assert parsed["status"] == "vulnerable"
        assert parsed["cve"] == "CVE-2026-80428"
        assert "CVE-2026-80428" in parsed["summary"]
        assert "9.22" in parsed["recommendation"]

    def test_parse_partial_result(self):
        raw = RawIliasResult(
            target="https://lms.test",
            base_url="https://lms.test",
            ltiauth_status=404,
            ltiauth_accessible=False,
            shib_logout_status=200,
            shib_logout_responsive=True,
            shib_response_snippet="<LogoutNotificationResponse/>",
            ilias_fingerprinted=True,
        )
        parsed = parse_ilias_result(raw)
        assert parsed["vulnerable"] is False
        assert parsed["status"] == "partial"
        assert "POTENTIALLY VULNERABLE" in parsed["summary"]

    def test_parse_safe_result(self):
        raw = RawIliasResult(
            target="https://lms.test",
            base_url="https://lms.test",
            ltiauth_status=200,
            ltiauth_accessible=True,
            shib_logout_status=403,
            shib_logout_responsive=False,
            ilias_fingerprinted=True,
        )
        parsed = parse_ilias_result(raw)
        assert parsed["vulnerable"] is False
        assert parsed["status"] == "safe"
        assert "SAFE" in parsed["summary"]

    def test_parse_not_applicable(self):
        raw = RawIliasResult(
            target="https://other.test",
            base_url="https://other.test",
            ltiauth_status=404,
            shib_logout_status=404,
            ilias_fingerprinted=False,
        )
        parsed = parse_ilias_result(raw)
        assert parsed["vulnerable"] is False
        assert parsed["status"] == "not_applicable"
        assert "NOT_APPLICABLE" in parsed["summary"]

    def test_parse_error(self):
        raw = RawIliasResult(target="https://lms.test", error="target is required")
        parsed = parse_ilias_result(raw)
        assert parsed["vulnerable"] is False
        assert parsed["status"] == "error"
        assert parsed["error"] == "target is required"


class TestIliasRceTool:
    def test_registration(self):
        ids = [t.tool_id for t in ALL_TOOLS]
        assert "ilias_rce_probe" in ids

    def test_spec_attributes(self):
        tool = IliasRceProbe()
        assert tool.spec.name == "ilias_rce_probe"
        assert tool.required_binary is None
        assert tool.scope_param == "target"
        assert tool.destructive is False
        assert tool.is_available() is True
        assert "target" in tool.spec.parameters["properties"]

    @patch("tradecraft.adapters.ilias_rce_probe.execute.execute")
    def test_tool_run(self, mock_exec):
        mock_exec.return_value = RawIliasResult(
            target="https://lms.test",
            base_url="https://lms.test",
        )
        tool = IliasRceProbe()
        res = tool.run(target="https://lms.test")
        assert res["target"] == "https://lms.test"
        assert res["vulnerable"] is False

    def test_profile_membership(self):
        web = load_profile("web")
        full = load_profile("full")
        assert "ilias_rce_probe" in web
        assert "ilias_rce_probe" in full
