from __future__ import annotations

import base64
from unittest.mock import MagicMock, patch

import mmh3
import requests

from tradecraft.adapters.favicon_correlator import execute as favicon_execute
from tradecraft.adapters.favicon_correlator import parse as favicon_parse
from tradecraft.tools.favicon_correlator import FaviconCorrelator


def test_compute_shodan_favicon_hash():
    content = b"fake favicon content for hash testing"
    expected_b64 = base64.encodebytes(content)
    expected_hash = mmh3.hash(expected_b64)

    calculated_hash = favicon_parse.compute_shodan_favicon_hash(content)
    assert calculated_hash == expected_hash
    assert isinstance(calculated_hash, int)


def test_parse_shodan_matches():
    data = {
        "matches": [
            {"ip_str": "198.51.100.1", "port": 443},
            {"ip_str": "203.0.113.5", "port": 80},
            {"ip_str": "198.51.100.1", "port": 8443},
            {"other_field": "no ip"},
        ],
        "total": 3,
    }
    ips = favicon_parse.parse_shodan_matches(data)
    assert ips == ["198.51.100.1", "203.0.113.5"]


def test_parse_shodan_matches_empty_and_malformed():
    assert favicon_parse.parse_shodan_matches({}) == []
    assert favicon_parse.parse_shodan_matches({"matches": []}) == []
    assert favicon_parse.parse_shodan_matches({"matches": "not a list"}) == []


def test_normalize_target_url():
    assert favicon_parse.normalize_target_url("exampleauto.com.br") == "https://exampleauto.com.br"
    assert favicon_parse.normalize_target_url("http://example.com") == "http://example.com"
    assert favicon_parse.normalize_target_url("https://example.com:8443") == "https://example.com:8443"


def test_execute_success():
    favicon_bytes = b"sample-favicon-data"
    expected_hash = favicon_parse.compute_shodan_favicon_hash(favicon_bytes)

    favicon_resp = MagicMock()
    favicon_resp.status_code = 200
    favicon_resp.content = favicon_bytes

    shodan_resp = MagicMock()
    shodan_resp.status_code = 200
    shodan_resp.json.return_value = {
        "matches": [{"ip_str": "1.2.3.4"}],
        "total": 1,
    }

    with patch("requests.get", side_effect=[favicon_resp, shodan_resp]) as mock_get:
        result = favicon_execute.execute("https://example.com", api_key="test-api-key")

    assert result.error is None
    assert result.favicon_hash == expected_hash
    assert result.shodan_json == {"matches": [{"ip_str": "1.2.3.4"}], "total": 1}

    assert mock_get.call_count == 2
    # Call 1: favicon fetch
    mock_get.assert_any_call("https://example.com/favicon.ico", timeout=10, verify=False)
    # Call 2: shodan search
    mock_get.assert_any_call(
        "https://api.shodan.io/shodan/host/search",
        params={"key": "test-api-key", "query": f"http.favicon.hash:{expected_hash}"},
        timeout=30,
    )


def test_execute_errors():
    # Empty inputs
    assert favicon_execute.execute("", "key").error == "Target cannot be empty"
    assert favicon_execute.execute("example.com", "").error == "SHODAN_API_KEY cannot be empty"

    # Favicon network failure
    with patch("requests.get", side_effect=requests.RequestException("connection failed")):
        res = favicon_execute.execute("example.com", "key")
        assert "failed to fetch favicon" in res.error

    # Favicon 404
    resp_404 = MagicMock(status_code=404, content=b"")
    with patch("requests.get", return_value=resp_404):
        res = favicon_execute.execute("example.com", "key")
        assert "no favicon at https://example.com/favicon.ico (status 404)" in res.error

    # Shodan network failure preserves computed favicon_hash
    favicon_resp = MagicMock(status_code=200, content=b"bytes")
    with patch("requests.get", side_effect=[favicon_resp, requests.RequestException("shodan down")]):
        res = favicon_execute.execute("example.com", "key")
        assert res.favicon_hash is not None
        assert "Shodan search request failed" in res.error

    # Shodan 401 unauthorized preserves computed favicon_hash
    shodan_401 = MagicMock(status_code=401)
    shodan_401.json.return_value = {"error": "Invalid API key"}
    shodan_401.text = "Invalid API key"
    with patch("requests.get", side_effect=[favicon_resp, shodan_401]):
        res = favicon_execute.execute("example.com", "key")
        assert res.favicon_hash is not None
        assert "Shodan API error (status 401): Invalid API key" in res.error


def test_tool_availability_and_run(monkeypatch):
    tool = FaviconCorrelator()

    # When SHODAN_API_KEY is unset
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    assert tool.is_available() is False
    res_no_key = tool.run("example.com")
    assert res_no_key["error"] == "SHODAN_API_KEY not configured in environment"
    assert res_no_key["correlated_ips"] == []

    # When SHODAN_API_KEY is set
    monkeypatch.setenv("SHODAN_API_KEY", "dummy-shodan-key")
    assert tool.is_available() is True

    raw_result = favicon_execute.RawFaviconResult(
        favicon_hash=12345678,
        shodan_json={"matches": [{"ip_str": "192.0.2.1"}]},
        error=None,
    )
    with patch("tradecraft.adapters.favicon_correlator.execute.execute", return_value=raw_result):
        res = tool.run("exampleauto.com.br")

    assert res["target"] == "exampleauto.com.br"
    assert res["favicon_hash"] == 12345678
    assert res["correlated_ips"] == ["192.0.2.1"]

    facts = tool.extract_facts({"target": "exampleauto.com.br"}, res)
    assert facts == [{"host": "exampleauto.com.br", "favicon_correlated_ips": ["192.0.2.1"]}]

    # Empty correlated IPs extracts no facts
    assert tool.extract_facts({"target": "exampleauto.com.br"}, {"correlated_ips": []}) == []
