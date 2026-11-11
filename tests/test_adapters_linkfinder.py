from unittest.mock import MagicMock, patch

from tradecraft.adapters.linkfinder.execute import (
    execute,
    find_script,
    normalize_target_url,
)
from tradecraft.adapters.linkfinder.parse import parse_endpoints


def test_normalize_target_url():
    assert normalize_target_url("example.com") == "https://example.com"
    assert normalize_target_url("http://example.com/app") == "http://example.com/app"
    assert normalize_target_url("https://example.com/") == "https://example.com/"
    assert normalize_target_url("") == ""


@patch("os.path.isfile")
def test_find_script(mock_isfile):
    mock_isfile.side_effect = lambda path: path == "/opt/LinkFinder/linkfinder.py"
    assert find_script() == "/opt/LinkFinder/linkfinder.py"


@patch("tradecraft.adapters.linkfinder.execute.find_script")
def test_execute_missing_script(mock_find):
    mock_find.return_value = None
    res = execute("https://example.com")
    assert res.error is not None
    assert "LinkFinder not found" in res.error


@patch("subprocess.run")
@patch("tradecraft.adapters.linkfinder.execute.find_script")
def test_execute_success(mock_find, mock_run):
    mock_find.return_value = "/opt/LinkFinder/linkfinder.py"
    mock_run.return_value = MagicMock(
        returncode=0,
        stdout="/api/v1/users\nhttps://auth.example.com/token\n",
        stderr="",
    )

    res = execute("example.com")
    assert res.error is None
    assert res.returncode == 0
    assert "/api/v1/users" in res.stdout
    assert res.target_url == "https://example.com"


def test_parse_endpoints():
    raw_stdout = """
Running against: https://example.com/main.js

/api/v1/users
/api/v2/items?filter=1
https://example.com/oauth/callback
/api/v1/users
Invalid input defined or SSL error for: something
    /indented/route
https://auth.example.com/token&amp;scope=all
"""
    endpoints = parse_endpoints(raw_stdout)
    assert len(endpoints) == 5
    assert "/api/v1/users" in endpoints
    assert "/api/v2/items?filter=1" in endpoints
    assert "/indented/route" in endpoints
    assert "https://auth.example.com/token&scope=all" in endpoints
    assert "https://example.com/oauth/callback" in endpoints
    # Must be sorted
    assert endpoints == sorted(endpoints)


def test_parse_endpoints_empty():
    assert parse_endpoints("") == []
    assert parse_endpoints("Just random text\nNo endpoints here\n") == []
