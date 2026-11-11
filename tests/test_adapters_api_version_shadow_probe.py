"""Unit tests for the api_version_shadow_probe adapter. Mocks requests.request."""
from __future__ import annotations

import urllib.parse
from unittest.mock import MagicMock, patch

from tradecraft.adapters.api_version_shadow_probe.execute import (
    MAX_VARIANTS,
    build_version_variants,
    execute,
    normalize_target_url,
)
from tradecraft.adapters.api_version_shadow_probe.parse import parse


def _resp(status_code, body=b""):
    resp = MagicMock()
    resp.status_code = status_code
    resp.content = body
    resp.headers = {"location": ""}
    return resp


def test_normalize_target_url_adds_https():
    assert normalize_target_url("api.example.com/v1/users") == "https://api.example.com/v1/users"
    assert normalize_target_url("http://api.example.com") == "http://api.example.com"
    assert normalize_target_url("") == ""


def test_build_version_variants_replaces_existing_version_segment():
    variants = build_version_variants("https://api.example.com/v2/users?active=1")
    urls = dict(variants)
    assert urls["replace_v2_with_v1"] == "https://api.example.com/v1/users?active=1"
    assert "replace_v2_with_beta" in urls
    for label, url in variants:
        assert urllib.parse.urlsplit(url).path != "/v2/users"


def test_build_version_variants_adds_prefixes_without_double_slashes():
    variants = build_version_variants("https://api.example.com/admin")
    urls = dict(variants)
    assert urls["api_v1_prefix"] == "https://api.example.com/api/v1/admin"
    assert urls["v1_prefix"] == "https://api.example.com/v1/admin"
    assert urls["api_legacy_prefix"] == "https://api.example.com/api/legacy/admin"
    for _, url in variants:
        path = urllib.parse.urlsplit(url).path
        assert "//" not in path
        assert path.startswith("/")


def test_build_version_variants_is_capped():
    variants = build_version_variants("https://api.example.com/v2/users")
    assert len(variants) <= MAX_VARIANTS
    assert len({url for _, url in variants}) == len(variants)


def test_execute_reports_variant_that_answers_without_auth():
    def fake_request(method, url, **kwargs):
        if url == "https://api.example.com/v2/users":
            return _resp(401, b"denied")
        if url == "https://api.example.com/v1/users":
            return _resp(200, b"[]")
        return _resp(404, b"not found")

    with patch("tradecraft.adapters.api_version_shadow_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.request.side_effect = fake_request
        raw = execute(target="https://api.example.com/v2/users")

    result = parse(raw)
    assert result["vulnerable"] is True
    assert result["baseline_status"] == 401
    assert [v["label"] for v in result["accessible_variants"]] == ["replace_v2_with_v1"]


def test_execute_baseline_already_open_short_circuits():
    calls = []

    def fake_request(method, url, **kwargs):
        calls.append(url)
        return _resp(200, b"ok")

    with patch("tradecraft.adapters.api_version_shadow_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.request.side_effect = fake_request
        raw = execute(target="https://api.example.com/v2/users")

    result = parse(raw)
    assert result["vulnerable"] is False
    assert "not auth-protected" in result["reason"]
    assert result["variants"] == []
    assert calls == ["https://api.example.com/v2/users"]


def test_execute_baseline_not_blocked_has_no_comparison():
    with patch("tradecraft.adapters.api_version_shadow_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.request.return_value = _resp(404, b"missing")
        raw = execute(target="https://api.example.com/v2/users")

    result = parse(raw)
    assert result["vulnerable"] is False
    assert "no auth boundary" in result["reason"]


def test_execute_blocked_baseline_with_no_open_variant():
    with patch("tradecraft.adapters.api_version_shadow_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.request.return_value = _resp(401, b"denied")
        raw = execute(target="https://api.example.com/v2/users")

    result = parse(raw)
    assert result["vulnerable"] is False
    assert result["reason"] == "no alternate version prefix answered 2xx unauthenticated"
    assert len(result["variants"]) > 0


def test_execute_rejects_state_mutating_methods():
    result = execute(target="https://api.example.com/v2/users", method="DELETE")
    assert result.error is not None
    assert "state-mutating" in result.error
    assert "http_write_request" in result.error
    assert parse(result) == {"target": "https://api.example.com/v2/users", "error": result.error}


def test_execute_network_error_is_reported():
    with patch("tradecraft.adapters.api_version_shadow_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.request.side_effect = Exception("boom")
        raw = execute(target="https://api.example.com/v2/users")

    result = parse(raw)
    assert result == {"target": "https://api.example.com/v2/users", "error": "boom"}
