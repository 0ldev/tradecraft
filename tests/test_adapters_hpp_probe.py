"""Unit tests for the hpp_probe adapter. Mocks requests.request."""
from __future__ import annotations

import json
import urllib.parse
from unittest.mock import MagicMock, patch

from tradecraft.adapters.hpp_probe.execute import (
    MAX_VARIANTS,
    execute,
    normalize_target_url,
)
from tradecraft.adapters.hpp_probe.parse import parse


def _resp(status_code=200, text="ok"):
    resp = MagicMock()
    resp.status_code = status_code
    resp.content = text.encode("utf-8")
    resp.text = text
    return resp


def test_normalize_target_url_adds_https():
    assert normalize_target_url("example.com/search?q=x") == "https://example.com/search?q=x"
    assert normalize_target_url("") == ""


def test_execute_requires_at_least_one_parameter():
    with patch("tradecraft.adapters.hpp_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.request.return_value = _resp()
        result = execute(target="https://example.com/")
    assert result.error is not None
    assert "no parameters to pollute" in result.error


def test_execute_duplicates_query_parameter_in_both_orderings():
    with patch("tradecraft.adapters.hpp_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.request.return_value = _resp()
        result = execute(target="https://example.com/search?q=test", params="q")

    assert result.error is None
    assert len(result.attempts) == 2
    for attempt in result.attempts:
        pairs = urllib.parse.parse_qsl(urllib.parse.urlsplit(attempt.url).query)
        values = [value for key, value in pairs if key == "q"]
        assert len(values) == 2
        assert "test" in values
        assert attempt.sentinel in values
    first = next(a for a in result.attempts if a.ordering == "original_then_sentinel")
    second = next(a for a in result.attempts if a.ordering == "sentinel_then_original")
    assert urllib.parse.parse_qsl(urllib.parse.urlsplit(first.url).query) == [
        ("q", "test"),
        ("q", first.sentinel),
    ]
    assert urllib.parse.parse_qsl(urllib.parse.urlsplit(second.url).query) == [
        ("q", second.sentinel),
        ("q", "test"),
    ]


def test_execute_duplicates_json_key_textually():
    with patch("tradecraft.adapters.hpp_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.request.return_value = _resp()
        result = execute(
            target="https://example.com/api",
            method="POST",
            body='{"role":"user"}',
            params="role",
        )

    first = next(a for a in result.attempts if a.ordering == "original_then_sentinel")
    second = next(a for a in result.attempts if a.ordering == "sentinel_then_original")
    # A JSON parser keeps the last duplicate key, so the textual ordering
    # decides which value wins.
    assert json.loads(first.body)["role"] == first.sentinel
    assert json.loads(second.body)["role"] == "user"


def test_execute_duplicates_form_body_parameter():
    with patch("tradecraft.adapters.hpp_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.request.return_value = _resp()
        result = execute(
            target="https://example.com/api",
            method="POST",
            body="role=user&next=%2Fhome",
            params="role",
        )

    assert len(result.attempts) == 2
    for attempt in result.attempts:
        pairs = urllib.parse.parse_qsl(attempt.body)
        values = [value for key, value in pairs if key == "role"]
        assert len(values) == 2
        assert "user" in values
        assert attempt.sentinel in values


def test_execute_reports_skipped_parameters():
    with patch("tradecraft.adapters.hpp_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.request.return_value = _resp()
        result = execute(target="https://example.com/search?q=test", params="absent")

    assert result.skipped_params == ["absent"]
    assert result.attempts == []


def test_parse_detects_sentinel_reflection():
    def fake_request(method, url, **kwargs):
        if "rs_hpp_" in url:
            sentinel = url.split("rs_hpp_")[1].split("&")[0]
            return _resp(200, f"echo rs_hpp_{sentinel}")
        return _resp(200, "baseline")

    with patch("tradecraft.adapters.hpp_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.request.side_effect = fake_request
        raw = execute(target="https://example.com/search?q=test", params="q")

    result = parse(raw)
    assert result["hpp_observed"] is True
    reflected = [a for a in result["attempts"] if a["classification"] == "sentinel_reflected"]
    assert reflected
    assert reflected[0]["value_used"] in ("first", "last")


def test_parse_reports_no_change_when_baseline_repeats():
    with patch("tradecraft.adapters.hpp_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.request.return_value = _resp(200, "same")
        raw = execute(target="https://example.com/search?q=test", params="q")

    result = parse(raw)
    assert result["hpp_observed"] is False
    assert {a["classification"] for a in result["attempts"]} == {"no_change"}


def test_execute_caps_variants_at_max():
    target = "https://example.com/search?" + "&".join(f"p{i}=v{i}" for i in range(10))
    with patch("tradecraft.adapters.hpp_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.request.return_value = _resp()
        result = execute(target=target)

    assert len(result.attempts) <= MAX_VARIANTS
    assert len(result.param_names) <= 5


def test_execute_rejects_state_mutating_methods():
    result = execute(target="https://example.com/search?q=test", method="PATCH", params="q")
    assert result.error is not None
    assert "state-mutating" in result.error
    assert "http_write_request" in result.error


def test_execute_network_error_is_reported():
    with patch("tradecraft.adapters.hpp_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.request.side_effect = Exception("boom")
        raw = execute(target="https://example.com/search?q=test", params="q")

    result = parse(raw)
    assert result["error"] == "boom"
