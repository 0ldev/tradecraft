"""Unit tests for csrf_probe adapter. Mocks requests.request."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from tradecraft.adapters.csrf_probe.execute import execute, parse_custom_headers
from tradecraft.adapters.csrf_probe.parse import parse


def _mock_response(status_code=200, text='{"ok":true}'):
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    return resp


def test_parse_custom_headers_strips_referer_and_origin():
    headers = parse_custom_headers("Referer: https://example.com\nOrigin: https://example.com\nCookie: session=xyz")
    assert "Referer" not in headers
    assert "Origin" not in headers
    assert headers["Cookie"] == "session=xyz"


def test_execute_rejects_invalid_body():
    result = execute(target="https://example.com/account/email", body="bad", token_param="csrf_token")
    assert result.error is not None


def test_execute_sends_exactly_two_attempts_token_removed_and_replaced():
    captured_bodies = []

    def fake_request(method, url, json=None, **kwargs):
        captured_bodies.append(json)
        return _mock_response()

    with patch("tradecraft.adapters.csrf_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.request.side_effect = fake_request
        result = execute(
            target="https://example.com/account/email",
            body='{"email":"new@example.com","csrf_token":"abc123"}',
            token_param="csrf_token",
        )

    assert len(result.attempts) == 2
    assert {a.variant for a in result.attempts} == {"token_removed", "token_replaced"}
    assert "csrf_token" not in captured_bodies[0]
    assert captured_bodies[1]["csrf_token"] != "abc123"


def test_parse_vulnerable_when_accepted_without_valid_token():
    with patch("tradecraft.adapters.csrf_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.request.return_value = _mock_response(status_code=200)
        raw = execute(target="https://example.com/account/email", body='{"email":"x","csrf_token":"abc"}', token_param="csrf_token")
    result = parse(raw)
    assert result["vulnerable"] is True
    assert set(result["accepted_variants"]) == {"token_removed", "token_replaced"}


def test_parse_not_vulnerable_when_rejected():
    with patch("tradecraft.adapters.csrf_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.request.return_value = _mock_response(status_code=403, text="Forbidden")
        raw = execute(target="https://example.com/account/email", body='{"email":"x","csrf_token":"abc"}', token_param="csrf_token")
    result = parse(raw)
    assert result["vulnerable"] is False
    assert all(a["classification"] == "rejected" for a in result["attempts"])
