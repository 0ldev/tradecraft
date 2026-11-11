"""Unit tests for the workflow_step_bypass_probe adapter. Mocks requests.request."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from tradecraft.adapters.workflow_step_bypass_probe.execute import execute
from tradecraft.adapters.workflow_step_bypass_probe.parse import parse


def _resp(status_code=200, text="", location=""):
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.headers = {"location": location}
    return resp


def _run(status_code, text="", location="", **kwargs):
    with patch("tradecraft.adapters.workflow_step_bypass_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.request.return_value = _resp(status_code, text, location)
        return execute(target="https://shop.example.com/api/checkout/42/confirm", **kwargs)


def test_accepted_confirmed_requires_marker():
    raw = _run(200, text='{"status":"paid"}', success_marker='"status":"paid"')
    result = parse(raw)
    assert result["classification"] == "accepted_confirmed"
    assert result["step_bypass_suspected"] is True
    assert result["marker_found"] is True


def test_accepted_unconfirmed_without_marker():
    raw = _run(200, text="ok")
    result = parse(raw)
    assert result["classification"] == "accepted_unconfirmed"
    assert result["step_bypass_suspected"] is True
    assert result["marker_found"] is False


def test_blocked_401_and_403():
    assert parse(_run(401)).get("classification") == "blocked"
    assert parse(_run(403)).get("classification") == "blocked"


def test_redirected_reports_location():
    result = parse(_run(302, location="https://shop.example.com/cart"))
    assert result["classification"] == "redirected"
    assert result["location"] == "https://shop.example.com/cart"


def test_rejected_and_server_error():
    assert parse(_run(422)).get("classification") == "rejected"
    assert parse(_run(500)).get("classification") == "server_error"


def test_rejects_unsupported_method():
    result = execute(target="https://shop.example.com/step", method="TRACE")
    assert result.error is not None
    assert "unsupported method" in result.error


def test_empty_target_is_rejected():
    result = execute(target="")
    assert result.error == "empty target URL"


def test_network_error_is_reported():
    with patch("tradecraft.adapters.workflow_step_bypass_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.request.side_effect = Exception("boom")
        raw = execute(target="https://shop.example.com/step")

    result = parse(raw)
    assert result["error"] == "boom"


def test_sends_exactly_one_request():
    calls = []

    def fake_request(method, url, **kwargs):
        calls.append((method, url, kwargs.get("data")))
        return _resp(200, "ok")

    with patch("tradecraft.adapters.workflow_step_bypass_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.request.side_effect = fake_request
        execute(
            target="https://shop.example.com/api/checkout/42/confirm",
            method="post",
            body='{"order_id":"42"}',
        )

    assert len(calls) == 1
    assert calls[0][0] == "POST"
    assert calls[0][2] == '{"order_id":"42"}'
