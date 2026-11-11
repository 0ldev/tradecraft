"""
Unit tests for php_cgi_arg_injection_probe adapter and tool.
Mocks all network calls so tests run fully offline.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from tradecraft.adapters.php_cgi_arg_injection_probe.execute import (
    PROBE_TOKEN,
    PhpCgiProbeAttempt,
    RawPhpCgiResult,
    execute,
    normalize_target_url,
)
from tradecraft.adapters.php_cgi_arg_injection_probe.parse import parse_php_cgi_result
from tradecraft.tools.php_cgi_arg_injection_probe import PhpCgiArgInjectionProbe
from tradecraft.tools.profiles import load_profile
from tradecraft.tools.registry import ALL_TOOLS


class TestPhpCgiArgInjectionExecute:
    def test_normalize_target_url(self):
        assert normalize_target_url("example.com") == "https://example.com"
        assert normalize_target_url("http://xampp.test/") == "http://xampp.test"
        assert normalize_target_url("  https://store.local/test  ") == "https://store.local/test"

    def test_execute_empty_target(self):
        res = execute("")
        assert res.error == "target is required"
        assert not res.attempts

    @patch("requests.Session")
    def test_execute_vulnerable_response(self, mock_session_cls):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        resp = MagicMock()
        resp.status_code = 200
        resp.text = f"{PROBE_TOKEN}\n<!DOCTYPE html>..."
        mock_session.post.return_value = resp

        res = execute("https://vulnerable-xampp.test")
        assert res.target == "https://vulnerable-xampp.test"
        assert len(res.attempts) == 1
        assert res.attempts[0].reflected_token is True
        assert res.attempts[0].status_code == 200

    @patch("requests.Session")
    def test_execute_safe_response(self, mock_session_cls):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        resp = MagicMock()
        resp.status_code = 200
        resp.text = "<html>Welcome to our PHP site</html>"
        mock_session.post.return_value = resp

        res = execute("https://safe-php.test")
        assert len(res.attempts) == 4
        for a in res.attempts:
            assert a.reflected_token is False

    @patch("requests.Session")
    def test_execute_custom_path(self, mock_session_cls):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        resp = MagicMock()
        resp.status_code = 200
        resp.text = "Hello"
        mock_session.post.return_value = resp

        res = execute("https://custom.test", path="/test_script.php")
        assert len(res.attempts) == 1
        assert "/test_script.php" in res.attempts[0].url

    @patch("requests.Session")
    def test_execute_network_error(self, mock_session_cls):
        mock_session = MagicMock()
        mock_session_cls.return_value = mock_session

        mock_session.post.side_effect = requests.exceptions.ConnectionError("Connection timed out")

        res = execute("https://offline-target.test", path="/index.php")
        assert len(res.attempts) == 1
        assert "timed out" in str(res.attempts[0].error)


class TestPhpCgiArgInjectionParse:
    def test_parse_vulnerable_result(self):
        raw = RawPhpCgiResult(
            target="https://target.test",
            base_url="https://target.test",
            probe_token=PROBE_TOKEN,
            attempts=[
                PhpCgiProbeAttempt(
                    url="https://target.test/index.php?%add+allow_url_include%3don...",
                    status_code=200,
                    reflected_token=True,
                    body_snippet=PROBE_TOKEN,
                )
            ],
        )
        parsed = parse_php_cgi_result(raw)
        assert parsed["vulnerable"] is True
        assert parsed["status"] == "vulnerable"
        assert "CVE-2024-4577" in parsed["summary"]
        assert "8.3.8+" in parsed["recommendation"]
        assert parsed["matched_url"] == raw.attempts[0].url

    def test_parse_safe_result(self):
        raw = RawPhpCgiResult(
            target="https://target.test",
            base_url="https://target.test",
            probe_token=PROBE_TOKEN,
            attempts=[
                PhpCgiProbeAttempt(
                    url="https://target.test/index.php?...",
                    status_code=200,
                    reflected_token=False,
                )
            ],
        )
        parsed = parse_php_cgi_result(raw)
        assert parsed["vulnerable"] is False
        assert parsed["status"] == "safe"
        assert "SAFE" in parsed["summary"]

    def test_parse_not_applicable(self):
        raw = RawPhpCgiResult(
            target="https://target.test",
            base_url="https://target.test",
            probe_token=PROBE_TOKEN,
            attempts=[
                PhpCgiProbeAttempt(url="https://target.test/index.php", status_code=404),
                PhpCgiProbeAttempt(url="https://target.test/", status_code=404),
            ],
        )
        parsed = parse_php_cgi_result(raw)
        assert parsed["vulnerable"] is False
        assert parsed["status"] == "not_applicable"
        assert "NOT_APPLICABLE" in parsed["summary"]

    def test_parse_error(self):
        raw = RawPhpCgiResult(target="https://target.test", error="target is required")
        parsed = parse_php_cgi_result(raw)
        assert parsed["vulnerable"] is False
        assert parsed["status"] == "error"
        assert parsed["error"] == "target is required"


class TestPhpCgiArgInjectionTool:
    def test_registration(self):
        ids = [t.tool_id for t in ALL_TOOLS]
        assert "php_cgi_arg_injection_probe" in ids

    def test_spec_attributes(self):
        tool = PhpCgiArgInjectionProbe()
        assert tool.spec.name == "php_cgi_arg_injection_probe"
        assert tool.required_binary is None
        assert tool.scope_param == "target"
        assert tool.destructive is False
        assert tool.is_available() is True
        assert "target" in tool.spec.parameters["properties"]

    @patch("tradecraft.adapters.php_cgi_arg_injection_probe.execute.execute")
    def test_tool_run(self, mock_exec):
        mock_exec.return_value = RawPhpCgiResult(
            target="https://example.com",
            attempts=[],
        )
        tool = PhpCgiArgInjectionProbe()
        res = tool.run(target="https://example.com")
        assert res["target"] == "https://example.com"
        assert res["vulnerable"] is False

    def test_profile_membership(self):
        web = load_profile("web")
        full = load_profile("full")
        assert "php_cgi_arg_injection_probe" in web
        assert "php_cgi_arg_injection_probe" in full
