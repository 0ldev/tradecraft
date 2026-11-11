"""Unit tests for oauth_redirect_probe adapter. Mocks requests.get."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from tradecraft.adapters.oauth_redirect_probe.execute import execute
from tradecraft.adapters.oauth_redirect_probe.parse import parse

TARGET = "https://idp.example.com/oauth/authorize?client_id=abc&response_type=code&redirect_uri=https://app.example.com/callback"


def _mock_response(status_code=200, location="", text=""):
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = {"location": location} if location else {}
    resp.text = text
    return resp


def test_execute_errors_without_redirect_uri_param():
    result = execute(target="https://idp.example.com/oauth/authorize?client_id=abc")
    assert result.error is not None


def test_execute_sends_original_then_each_variant():
    with patch("tradecraft.adapters.oauth_redirect_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.get.return_value = _mock_response(status_code=200, text="login page")
        result = execute(target=TARGET)
    assert result.error is None
    assert result.original_redirect_uri == "https://app.example.com/callback"
    techniques = {a.technique for a in result.attempts}
    assert "subdomain_trick" in techniques
    assert "at_bypass" in techniques
    assert "scheme_downgrade" in techniques


def test_parse_flags_accepted_pre_auth_when_location_matches_attacker_host():
    with patch("tradecraft.adapters.oauth_redirect_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception

        def fake_get(url, **kwargs):
            if "evil." in url or "evil-tradecraft-probe" in url:
                return _mock_response(status_code=302, location="https://evil.app.example.com/callback?code=xyz")
            return _mock_response(status_code=200, text="login page")

        mock_requests.get.side_effect = fake_get
        raw = execute(target=TARGET)
    result = parse(raw)
    assert result["vulnerable"] is True
    assert "subdomain_trick" in result["accepted_techniques"]


def test_parse_rejected_on_error_response():
    with patch("tradecraft.adapters.oauth_redirect_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.get.return_value = _mock_response(status_code=400, text='{"error":"invalid_request"}')
        raw = execute(target=TARGET)
    result = parse(raw)
    assert result["vulnerable"] is False
    assert all(a["classification"] == "rejected" for a in result["attempts"])


def test_parse_inconclusive_when_same_shape_as_original():
    with patch("tradecraft.adapters.oauth_redirect_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.get.return_value = _mock_response(status_code=200, text="login page")
        raw = execute(target=TARGET)
    result = parse(raw)
    assert result["vulnerable"] is False
    assert all(a["classification"] == "inconclusive_requires_login" for a in result["attempts"])
