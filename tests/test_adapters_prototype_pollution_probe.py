"""Unit tests for prototype_pollution_probe adapter. Mocks requests."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from tradecraft.adapters.prototype_pollution_probe.execute import execute
from tradecraft.adapters.prototype_pollution_probe.parse import parse


def _mock_response(status_code=200, text=""):
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    return resp


def test_execute_rejects_invalid_baseline_body():
    result = execute(target="https://example.com/api/search", body="not-json")
    assert result.error is not None


def test_execute_sends_four_vectors():
    with patch("tradecraft.adapters.prototype_pollution_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.get.return_value = _mock_response()
        mock_requests.post.return_value = _mock_response()
        result = execute(target="https://example.com/api/search")
    assert result.error is None
    vectors = {a.vector for a in result.attempts}
    assert vectors == {"query___proto__", "query_constructor_prototype", "json___proto__", "json_constructor_prototype"}


def test_parse_flags_direct_reflection():
    with patch("tradecraft.adapters.prototype_pollution_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception

        def fake_get(url, params=None, **kwargs):
            return _mock_response(status_code=200, text="")

        def fake_post(url, json=None, **kwargs):
            return _mock_response(status_code=200, text='{"polluted": true}')

        mock_requests.get.side_effect = fake_get
        mock_requests.post.side_effect = fake_post
        raw = execute(target="https://example.com/api/search")
        # Force the marker value into the mocked POST response to simulate reflection.
        raw.attempts = [a for a in raw.attempts]
        for a in raw.attempts:
            if a.vector.startswith("json"):
                a.body = f'{{"{raw.marker_property}": "{raw.marker_value}"}}'
    result = parse(raw)
    assert result["vulnerable"] is True
    assert "json___proto__" in result["reflected_vectors"]


def test_parse_leaked_cross_endpoint_via_verify_url():
    with patch("tradecraft.adapters.prototype_pollution_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.get.side_effect = [
            _mock_response(status_code=200, text=""),  # query___proto__
            _mock_response(status_code=200, text=""),  # query_constructor_prototype
            _mock_response(status_code=200, text="leaked-marker-will-be-injected"),  # verify_url
        ]
        mock_requests.post.return_value = _mock_response(status_code=200, text="")
        raw = execute(target="https://example.com/api/search", verify_url="https://example.com/api/profile")
        raw.verify_body = f"pollution reached here: {raw.marker_value}"
    result = parse(raw)
    assert result["leaked_cross_endpoint"] is True
    assert result["vulnerable"] is True


def test_parse_clean_result():
    with patch("tradecraft.adapters.prototype_pollution_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.get.return_value = _mock_response()
        mock_requests.post.return_value = _mock_response()
        raw = execute(target="https://example.com/api/search")
    result = parse(raw)
    assert result["vulnerable"] is False
