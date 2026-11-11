"""
Unit tests for sensitive_file_probe adapter (execution and parsing).
Mocks requests.get; no real network calls.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from tradecraft.adapters.sensitive_file_probe.execute import (
    RawFileFetch,
    RawSensitiveFileResult,
    execute,
    normalize_target_url,
)
from tradecraft.adapters.sensitive_file_probe.parse import parse


def test_normalize_target_url():
    assert normalize_target_url("example.com") == "https://example.com"
    assert normalize_target_url("https://example.com/") == "https://example.com"
    assert normalize_target_url("") == ""


def _mock_response(status_code=404, content_type="text/html", text="<html>not found</html>"):
    resp = MagicMock()
    resp.status_code = status_code
    resp.headers = {"content-type": content_type}
    resp.text = text
    return resp


def test_execute_baseline_error_short_circuits():
    with patch("tradecraft.adapters.sensitive_file_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.get.side_effect = Exception("boom")
        result = execute(target="https://example.com")
    assert result.error is not None
    assert result.candidates == []


def test_execute_fetches_baseline_then_all_candidates():
    baseline_resp = _mock_response(status_code=404)
    env_resp = _mock_response(status_code=200, content_type="text/plain", text="DB_PASSWORD=supersecret\nAPP_KEY=abc")

    def fake_get(url, **kwargs):
        if "tradecraft-nonexistent" in url:
            return baseline_resp
        if url.endswith("/.env"):
            return env_resp
        return _mock_response(status_code=404)

    with patch("tradecraft.adapters.sensitive_file_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.get.side_effect = fake_get
        result = execute(target="https://example.com")

    assert result.error is None
    assert result.baseline.status_code == 404
    assert len(result.candidates) == 16
    env_entry = next(c for c in result.candidates if c.path == "/.env")
    assert env_entry.status_code == 200
    assert "DB_PASSWORD" in env_entry.body


def test_parse_flags_env_hit_and_ignores_soft_404s():
    baseline = RawFileFetch(path="/tradecraft-nonexistent-x.probe", status_code=200, content_type="text/html", body="<html>Not Found</html>")
    candidates = [
        RawFileFetch(path="/.env", status_code=200, content_type="text/plain", body="DB_PASSWORD=supersecret\nAPP_KEY=abc"),
        RawFileFetch(path="/.git/config", status_code=200, content_type="text/html", body="<html>Not Found</html>"),
        RawFileFetch(path="/backup.sql", status_code=404, content_type="text/html", body=""),
    ]
    raw = RawSensitiveFileResult(target="https://example.com", baseline=baseline, candidates=candidates)
    result = parse(raw)

    assert result["hits_found"] == 1
    assert result["hits"][0]["path"] == "/.env"
    assert "DB_PASSWORD" in result["hits"][0]["body_snippet"]
    checked_paths = {c["path"] for c in result["checked"]}
    assert "/.git/config" in checked_paths
    git_entry = next(c for c in result["checked"] if c["path"] == "/.git/config")
    assert git_entry["hit"] is False


def test_parse_reports_top_level_error():
    raw = RawSensitiveFileResult(target="https://down.example", error="Connection refused")
    result = parse(raw)
    assert result == {"target": "https://down.example", "error": "Connection refused"}
