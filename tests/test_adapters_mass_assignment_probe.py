"""Unit tests for mass_assignment_probe adapter. Mocks requests.request."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from tradecraft.adapters.mass_assignment_probe.execute import execute
from tradecraft.adapters.mass_assignment_probe.parse import parse


def _mock_response(status_code=200, text='{"ok":true}'):
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    return resp


def test_execute_rejects_invalid_baseline_body():
    result = execute(target="https://api.example.com/users/1", body="not-json")
    assert result.error is not None
    assert "invalid baseline" in result.error


def test_execute_skips_fields_already_in_baseline_and_caps_at_eight():
    with patch("tradecraft.adapters.mass_assignment_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.request.return_value = _mock_response()
        result = execute(
            target="https://api.example.com/users/1",
            body='{"name": "Alice", "role": "user"}',
        )
    assert result.error is None
    tested_fields = {a.field for a in result.attempts}
    assert "role" not in tested_fields  # already in baseline
    assert len(result.attempts) <= 8


def test_execute_boolean_field_gets_true_value():
    with patch("tradecraft.adapters.mass_assignment_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.request.return_value = _mock_response()
        result = execute(
            target="https://api.example.com/users/1",
            body='{"name": "Alice"}',
            candidate_fields="isAdmin,price",
        )
    is_admin_attempt = next(a for a in result.attempts if a.field == "isAdmin")
    price_attempt = next(a for a in result.attempts if a.field == "price")
    assert is_admin_attempt.injected_value is True
    assert price_attempt.injected_value == 0


def test_parse_confirms_field_echoed_back():
    with patch("tradecraft.adapters.mass_assignment_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.request.return_value = _mock_response(status_code=200, text='{"name":"Alice","isAdmin":true}')
        raw = execute(target="https://api.example.com/users/1", body='{"name":"Alice"}', candidate_fields="isAdmin")
    result = parse(raw)
    assert result["confirmed_accepted"] == 1
    assert result["attempts"][0]["classification"] == "accepted_confirmed"


def test_parse_rejected_validation_status():
    with patch("tradecraft.adapters.mass_assignment_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.request.return_value = _mock_response(status_code=422, text='{"error":"unknown field"}')
        raw = execute(target="https://api.example.com/users/1", body='{"name":"Alice"}', candidate_fields="isAdmin")
    result = parse(raw)
    assert result["confirmed_accepted"] == 0
    assert result["attempts"][0]["classification"] == "rejected_validation"


def test_parse_top_level_error():
    result = parse(execute(target="https://api.example.com", body="bad"))
    assert "error" in result
