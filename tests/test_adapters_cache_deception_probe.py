from unittest.mock import MagicMock, patch

import requests

from tradecraft.adapters.cache_deception_probe import execute as cd_execute
from tradecraft.adapters.cache_deception_probe import parse as cd_parse
from tradecraft.adapters.cache_deception_probe.execute import DECEPTION_SUFFIXES

TARGET = "https://example.com/account/settings"
MARKER = "alice@example.com"
PATCH_GET = "tradecraft.adapters.cache_deception_probe.execute.requests.get"


def _resp(status: int, body: str) -> MagicMock:
    r = MagicMock()
    r.status_code = status
    r.text = body
    return r


def test_confirmed_deception_same_crafted_url_both_requests():
    first = DECEPTION_SUFFIXES[0]
    expected_url = f"{TARGET}{first}"
    with patch(PATCH_GET) as mock_get:
        mock_get.side_effect = [
            _resp(200, f"Welcome {MARKER}"),
            _resp(200, f"Welcome {MARKER}"),
        ]
        attempt = cd_execute.attempt_suffix(
            TARGET, first, {"Cookie": "session=xyz"}, MARKER
        )
    assert attempt.authed_marker_found is True
    assert attempt.clean_marker_found is True
    assert attempt.deception_confirmed is True
    assert attempt.error is None
    assert mock_get.call_count == 2
    assert mock_get.call_args_list[0].args[0] == expected_url
    assert mock_get.call_args_list[1].args[0] == expected_url
    # Auth header only on the first request, never on the verification request.
    assert mock_get.call_args_list[0].kwargs["headers"]["Cookie"] == "session=xyz"
    assert "Cookie" not in mock_get.call_args_list[1].kwargs["headers"]


def test_not_confirmed_when_clean_response_lacks_marker():
    first = DECEPTION_SUFFIXES[0]
    with patch(PATCH_GET) as mock_get:
        mock_get.side_effect = [
            _resp(200, f"Welcome {MARKER}"),
            _resp(200, "Login required"),
        ]
        attempt = cd_execute.attempt_suffix(TARGET, first, {}, MARKER)
    assert attempt.authed_marker_found is True
    assert attempt.clean_marker_found is False
    assert attempt.deception_confirmed is False
    assert mock_get.call_count == 2


def test_authed_request_without_marker_skips_clean_request():
    first = DECEPTION_SUFFIXES[0]
    with patch(PATCH_GET) as mock_get:
        mock_get.return_value = _resp(404, "not found")
        attempt = cd_execute.attempt_suffix(TARGET, first, {}, MARKER)
    assert attempt.authed_marker_found is False
    assert attempt.deception_confirmed is False
    assert mock_get.call_count == 1


def test_authed_request_exception_sets_error_and_skips_clean():
    first = DECEPTION_SUFFIXES[0]
    with patch(PATCH_GET) as mock_get:
        mock_get.side_effect = requests.ConnectionError("boom")
        attempt = cd_execute.attempt_suffix(TARGET, first, {}, MARKER)
    assert attempt.error is not None
    assert "authenticated request failed" in attempt.error
    assert attempt.deception_confirmed is False
    assert mock_get.call_count == 1


def test_clean_request_exception_sets_error_not_confirmed():
    first = DECEPTION_SUFFIXES[0]
    with patch(PATCH_GET) as mock_get:
        mock_get.side_effect = [
            _resp(200, f"Welcome {MARKER}"),
            requests.Timeout("slow"),
        ]
        attempt = cd_execute.attempt_suffix(TARGET, first, {}, MARKER)
    assert attempt.error is not None
    assert "clean (unauthenticated) request failed" in attempt.error
    assert attempt.deception_confirmed is False


def test_execute_tries_all_suffixes_even_after_confirmation():
    with patch(PATCH_GET) as mock_get:
        mock_get.side_effect = lambda url, **kw: _resp(200, f"Welcome {MARKER}")
        result = cd_execute.execute(target=TARGET, success_marker=MARKER, auth_headers="Cookie: s=1")
    assert len(result) == 5
    assert len(DECEPTION_SUFFIXES) == 5
    assert all(a.deception_confirmed for a in result)
    parsed = cd_parse.parse(result)
    assert parsed["vulnerable"] is True
    assert parsed["confirmed_suffixes"] == list(DECEPTION_SUFFIXES)
    assert parsed["tested_suffixes"] == list(DECEPTION_SUFFIXES)
    assert "authed_body" not in parsed["attempts"][0]
    assert "clean_body" not in parsed["attempts"][0]


def test_empty_target_returns_error_entry():
    result = cd_execute.execute(target="", success_marker="x", auth_headers="")
    assert len(result) == 1
    assert result[0].error is not None
    assert "empty target" in result[0].error
    assert cd_parse.parse(result) == {"error": result[0].error}


def test_build_crafted_url_appends_suffix():
    assert (
        cd_execute.build_crafted_url("https://example.com/account", "/nonexistent.css")
        == "https://example.com/account/nonexistent.css"
    )


def test_build_crafted_url_strips_trailing_slash():
    assert (
        cd_execute.build_crafted_url("https://example.com/account/", "/nonexistent.css")
        == "https://example.com/account/nonexistent.css"
    )
