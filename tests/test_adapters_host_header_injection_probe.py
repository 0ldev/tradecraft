"""Unit tests for host_header_injection_probe adapter. Mocks requests.request."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from tradecraft.adapters.host_header_injection_probe.execute import execute, normalize_target_url
from tradecraft.adapters.host_header_injection_probe.parse import parse


def _mock_response(status_code=200, location="", text=""):
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = {"location": location} if location else {}
    resp.text = text
    return resp


def test_normalize_target_url():
    assert normalize_target_url("example.com") == "https://example.com"
    assert normalize_target_url("") == ""


def test_execute_sends_one_request_per_default_header():
    with patch("tradecraft.adapters.host_header_injection_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.request.return_value = _mock_response()
        result = execute(target="https://example.com/forgot-password")
    assert result.error is None
    assert {a.header for a in result.attempts} == {"Host", "X-Forwarded-Host", "X-Forwarded-Server", "X-Host"}
    for a in result.attempts:
        assert a.marker_domain.endswith(".attacker-controlled.test")


def test_parse_flags_reflection_in_location_header():
    with patch("tradecraft.adapters.host_header_injection_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception

        def fake_request(method, url, headers, **kwargs):
            marker = headers.get("X-Forwarded-Host", "")
            if marker:
                return _mock_response(status_code=302, location=f"https://{marker}/reset?token=abc")
            return _mock_response(status_code=200)

        mock_requests.request.side_effect = fake_request
        raw = execute(target="https://example.com/forgot-password", headers_to_test="X-Forwarded-Host")
    result = parse(raw)
    assert result["vulnerable"] is True
    assert "X-Forwarded-Host" in result["reflected_headers"]


def test_parse_no_reflection_is_clean():
    with patch("tradecraft.adapters.host_header_injection_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.request.return_value = _mock_response(status_code=200, text="plain unrelated page")
        raw = execute(target="https://example.com/forgot-password", headers_to_test="Host")
    result = parse(raw)
    assert result["vulnerable"] is False
    assert result["reflected_headers"] == []


def test_parse_ignores_incidental_plain_text_marker():
    with patch("tradecraft.adapters.host_header_injection_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception

        def fake_request(method, url, headers, **kwargs):
            marker = headers.get("Host", "")
            return _mock_response(status_code=200, text=f"echoed header value: {marker} (not a URL)")

        mock_requests.request.side_effect = fake_request
        raw = execute(target="https://example.com", headers_to_test="Host")
    result = parse(raw)
    assert result["vulnerable"] is False
