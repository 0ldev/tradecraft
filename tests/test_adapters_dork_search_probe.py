from unittest.mock import MagicMock, patch

from tradecraft.adapters.dork_search_probe.execute import execute
from tradecraft.adapters.dork_search_probe.parse import parse


def _ok_response():
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {
        "items": [{"title": "Admin Panel", "link": "https://example.com/admin", "snippet": "Login here"}],
        "searchInformation": {"totalResults": "1"},
    }
    return resp


def test_missing_api_key(monkeypatch):
    monkeypatch.delenv("GOOGLE_CSE_API_KEY", raising=False)
    monkeypatch.setenv("GOOGLE_CSE_CX", "cx123")
    result = execute(query="site:example.com filetype:pdf")
    assert "GOOGLE_CSE_API_KEY environment variable not set" in result.error


def test_missing_cx(monkeypatch):
    monkeypatch.setenv("GOOGLE_CSE_API_KEY", "key123")
    monkeypatch.delenv("GOOGLE_CSE_CX", raising=False)
    result = execute(query="site:example.com filetype:pdf")
    assert "GOOGLE_CSE_CX environment variable not set" in result.error


def test_successful_call(monkeypatch):
    monkeypatch.setenv("GOOGLE_CSE_API_KEY", "key123")
    monkeypatch.setenv("GOOGLE_CSE_CX", "cx123")
    with patch("tradecraft.adapters.dork_search_probe.execute.requests.get", return_value=_ok_response()):
        result = execute(query="site:example.com inurl:admin")
    assert result.error is None
    assert len(result.items) == 1
    assert result.total_results_reported == "1"
    parsed = parse(result)
    assert parsed["result_count"] == 1
    assert parsed["results"][0] == {
        "title": "Admin Panel",
        "url": "https://example.com/admin",
        "snippet": "Login here",
    }


def test_non_200_response(monkeypatch):
    monkeypatch.setenv("GOOGLE_CSE_API_KEY", "key123")
    monkeypatch.setenv("GOOGLE_CSE_CX", "cx123")
    resp = MagicMock()
    resp.status_code = 403
    resp.text = "quota exceeded"
    with patch("tradecraft.adapters.dork_search_probe.execute.requests.get", return_value=resp):
        result = execute(query="site:example.com")
    assert "HTTP 403" in result.error
    assert "quota exceeded" in result.error


def test_non_json_200_response(monkeypatch):
    monkeypatch.setenv("GOOGLE_CSE_API_KEY", "key123")
    monkeypatch.setenv("GOOGLE_CSE_CX", "cx123")
    resp = MagicMock()
    resp.status_code = 200
    resp.json.side_effect = ValueError("bad json")
    with patch("tradecraft.adapters.dork_search_probe.execute.requests.get", return_value=resp):
        result = execute(query="site:example.com")
    assert "non-JSON" in result.error


def test_empty_query_checked_before_env(monkeypatch):
    monkeypatch.delenv("GOOGLE_CSE_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_CSE_CX", raising=False)
    result = execute(query="")
    assert result.error == "empty query"


def test_num_results_capped_at_10(monkeypatch):
    monkeypatch.setenv("GOOGLE_CSE_API_KEY", "key123")
    monkeypatch.setenv("GOOGLE_CSE_CX", "cx123")
    with patch("tradecraft.adapters.dork_search_probe.execute.requests.get", return_value=_ok_response()) as mock_get:
        execute(query="site:example.com", num_results=500)
    params = mock_get.call_args.kwargs["params"]
    assert params["num"] == 10
