"""
Unit tests for jenkins_unauth_probe adapter.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import requests

from tradecraft.adapters.jenkins_unauth_probe import execute as jenkins_execute


def _mock_get(url, **kwargs):
    resp = MagicMock()
    if url.rstrip("/") == "https://ci.example.com":
        resp.status_code = 200
        resp.headers = {"X-Jenkins": "2.401.3"}
    elif url.endswith("/whoAmI/api/json"):
        resp.status_code = 200
        resp.json.return_value = {"authenticated": False, "fullName": "anonymous", "id": "anonymous"}
    elif url.endswith("/script"):
        resp.status_code = 200
    elif url.endswith("/manage"):
        resp.status_code = 200
    elif url.endswith("/api/json"):
        resp.status_code = 200
        resp.json.return_value = {"mode": "NORMAL", "jobs": [{"name": "job1"}, {"name": "job2"}]}
    return resp


def test_full_positive_case():
    with patch("tradecraft.adapters.jenkins_unauth_probe.execute.requests.get", side_effect=_mock_get):
        result = jenkins_execute.execute(target="ci.example.com")

    assert result.is_jenkins is True
    assert result.jenkins_version == "2.401.3"
    assert result.script_console_reachable is True
    assert result.manage_reachable is True
    assert result.api_json["mode"] == "NORMAL"


def test_not_jenkins():
    resp = MagicMock(status_code=200, headers={})
    with patch("tradecraft.adapters.jenkins_unauth_probe.execute.requests.get", return_value=resp):
        result = jenkins_execute.execute(target="example.com")

    assert result.is_jenkins is False
    assert "X-Jenkins header not present" in result.error


def test_jenkins_but_script_console_gated():
    def side_effect(url, **kwargs):
        if url.rstrip("/") == "https://ci.example.com":
            return MagicMock(status_code=200, headers={"X-Jenkins": "2.401.3"})
        if url.endswith("/script"):
            return MagicMock(status_code=403)
        if url.endswith("/manage"):
            return MagicMock(status_code=403)
        return MagicMock(status_code=404)

    with patch("tradecraft.adapters.jenkins_unauth_probe.execute.requests.get", side_effect=side_effect):
        result = jenkins_execute.execute(target="ci.example.com")

    assert result.is_jenkins is True
    assert result.script_console_reachable is False
    assert result.manage_reachable is False


def test_connection_failure_on_root():
    with patch(
        "tradecraft.adapters.jenkins_unauth_probe.execute.requests.get",
        side_effect=requests.RequestException("refused"),
    ):
        result = jenkins_execute.execute(target="ci.example.com")

    assert result.is_jenkins is False
    assert "failed" in result.error


def test_normalize_base_url():
    assert jenkins_execute.normalize_base_url("ci.example.com") == "https://ci.example.com"
    assert jenkins_execute.normalize_base_url("http://ci.example.com/") == "http://ci.example.com"
    assert jenkins_execute.normalize_base_url("") == ""
