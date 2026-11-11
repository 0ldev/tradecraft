"""Unit tests for email_header_injection_probe adapter. Mocks requests.request."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from tradecraft.adapters.email_header_injection_probe.execute import DEFAULT_BCC_MARKER, execute, parse_custom_headers
from tradecraft.adapters.email_header_injection_probe.parse import parse


def _mock_response(status_code=200, text='{"ok":true}'):
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    return resp


def test_parse_custom_headers_includes_user_agent():
    headers = parse_custom_headers("Cookie: session=xyz")
    assert headers["Cookie"] == "session=xyz"
    assert "User-Agent" in headers


def test_execute_rejects_invalid_body():
    result = execute(target="https://example.com/contact", body="bad", field_to_inject="name")
    assert result.error is not None


def test_execute_requires_field_to_inject():
    result = execute(target="https://example.com/contact", body='{"name":"Alice"}', field_to_inject="")
    assert result.error is not None
    assert "field_to_inject" in result.error


def test_execute_sends_exactly_two_attempts_literal_and_urlencoded():
    captured_bodies = []

    def fake_request(method, url, json=None, **kwargs):
        captured_bodies.append(json)
        return _mock_response()

    with patch("tradecraft.adapters.email_header_injection_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.request.side_effect = fake_request
        result = execute(
            target="https://example.com/contact",
            body='{"name":"Alice","email":"a@example.com","message":"hi"}',
            field_to_inject="name",
        )

    assert len(result.attempts) == 2
    assert {a.variant for a in result.attempts} == {"crlf_literal", "crlf_urlencoded"}
    assert "\r\nBcc:" in captured_bodies[0]["name"]
    assert "%0d%0aBcc:" in captured_bodies[1]["name"]
    assert DEFAULT_BCC_MARKER in captured_bodies[0]["name"]


def test_execute_uses_custom_bcc_marker():
    with patch("tradecraft.adapters.email_header_injection_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.request.return_value = _mock_response()
        result = execute(
            target="https://example.com/contact", body='{"name":"Alice"}',
            field_to_inject="name", bcc_marker="custom@attacker.test",
        )
    assert result.bcc_marker == "custom@attacker.test"


def test_parse_vulnerable_when_accepted():
    with patch("tradecraft.adapters.email_header_injection_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.request.return_value = _mock_response(status_code=200)
        raw = execute(target="https://example.com/contact", body='{"name":"Alice"}', field_to_inject="name")
    result = parse(raw)
    assert result["vulnerable"] is True
    assert set(result["accepted_variants"]) == {"crlf_literal", "crlf_urlencoded"}
    assert "mail_access_probe" in result["summary"]


def test_parse_not_vulnerable_when_rejected():
    with patch("tradecraft.adapters.email_header_injection_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.request.return_value = _mock_response(status_code=400, text="Bad Request")
        raw = execute(target="https://example.com/contact", body='{"name":"Alice"}', field_to_inject="name")
    result = parse(raw)
    assert result["vulnerable"] is False
    assert all(a["classification"] == "rejected" for a in result["attempts"])


def test_parse_top_level_error():
    result = parse(execute(target="https://example.com/contact", body="bad", field_to_inject="name"))
    assert "error" in result
