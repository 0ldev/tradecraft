from unittest.mock import MagicMock, patch

import requests

from tradecraft.adapters.dangling_resource_probe.execute import (
    execute,
    normalize_host_url,
)
from tradecraft.adapters.dangling_resource_probe.parse import parse

GET_PATH = "tradecraft.adapters.dangling_resource_probe.execute.requests.get"


def _resp(body: str, status: int = 404) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.text = body
    return resp


def test_github_pages_match():
    with patch(GET_PATH, return_value=_resp("<h1>There isn't a GitHub Pages site here.</h1>")):
        raw = execute(target="forgotten.example.com")
    assert raw.matched_provider == "github_pages"
    assert raw.matched_signature == "There isn't a GitHub Pages site here."
    parsed = parse(raw)
    assert parsed["dangling"] is True
    assert parsed["error"] is None


def test_heroku_match():
    with patch(GET_PATH, return_value=_resp("<title>No such app</title>")):
        raw = execute(target="forgotten.example.com")
    assert raw.matched_provider == "heroku"


def test_azure_match():
    with patch(GET_PATH, return_value=_resp("404 Web Site not found.")):
        raw = execute(target="forgotten.example.com")
    assert raw.matched_provider == "azure_web_app"


def test_no_match_generic_body():
    with patch(GET_PATH, return_value=_resp("<html>Welcome</html>", status=200)):
        raw = execute(target="forgotten.example.com")
    assert raw.matched_provider is None
    assert raw.matched_signature is None
    assert raw.status_code == 200
    assert parse(raw)["dangling"] is False


def test_request_exception_sets_error():
    with patch(GET_PATH, side_effect=requests.RequestException("boom")):
        raw = execute(target="forgotten.example.com")
    assert raw.error is not None
    assert "request failed" in raw.error
    parsed = parse(raw)
    assert "request failed" in parsed["error"]
    assert "dangling" not in parsed


def test_empty_target_sets_error():
    with patch(GET_PATH) as get:
        raw = execute(target="")
    assert "empty target provided" in raw.error
    get.assert_not_called()


def test_normalize_host_url_bare_host():
    assert normalize_host_url("forgotten.example.com") == (
        "https://forgotten.example.com",
        "forgotten.example.com",
    )


def test_normalize_host_url_with_scheme_and_path():
    assert normalize_host_url("http://forgotten.example.com/path") == (
        "http://forgotten.example.com/path",
        "forgotten.example.com",
    )


def test_normalize_host_url_empty():
    assert normalize_host_url("") == ("", "")
