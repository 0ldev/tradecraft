from __future__ import annotations

from unittest.mock import MagicMock, patch

import requests

from tradecraft.adapters.race_condition_probe.execute import MAX_REQUESTS, _normalize_url, execute
from tradecraft.adapters.race_condition_probe.parse import parse

PATCH_TARGET = "tradecraft.adapters.race_condition_probe.execute.requests.request"
MARKER = "coupon redeemed"


def _resp(status: int, body: str) -> MagicMock:
    r = MagicMock()
    r.status_code = status
    r.text = body
    return r


def test_likely_race_condition_when_all_attempts_succeed():
    with patch(PATCH_TARGET, return_value=_resp(200, f"OK {MARKER}")) as mock_req:
        result = execute(url="https://example.com/redeem", success_marker=MARKER)

    assert mock_req.call_count == 5
    assert result.requested_count == 5
    assert result.success_count == 5
    assert result.likely_race_condition is True

    summary = parse(result)
    assert summary["success_count"] == 5
    assert summary["likely_race_condition"] is True


def test_no_race_condition_when_only_first_attempt_succeeds():
    responses = [_resp(200, f"OK {MARKER}")] + [_resp(200, "already redeemed") for _ in range(4)]
    with patch(PATCH_TARGET, side_effect=responses):
        result = execute(url="https://example.com/redeem", success_marker=MARKER)

    assert result.success_count == 1
    assert result.likely_race_condition is False


def test_request_count_is_hard_capped_at_max():
    with patch(PATCH_TARGET, return_value=_resp(200, "ok")) as mock_req:
        result = execute(url="https://example.com/redeem", request_count=1000)

    assert MAX_REQUESTS == 20
    assert result.requested_count == 20
    assert mock_req.call_count == 20


def test_request_count_floor_is_two():
    with patch(PATCH_TARGET, return_value=_resp(200, "ok")) as mock_req:
        result = execute(url="https://example.com/redeem", request_count=1)

    assert result.requested_count == 2
    assert mock_req.call_count == 2


def test_request_exception_on_one_attempt_is_isolated():
    responses = [
        _resp(200, f"OK {MARKER}"),
        requests.RequestException("connection reset"),
        _resp(200, f"OK {MARKER}"),
        _resp(200, "already redeemed"),
        _resp(200, "already redeemed"),
    ]
    with patch(PATCH_TARGET, side_effect=responses):
        result = execute(url="https://example.com/redeem", success_marker=MARKER)

    errored = [a for a in result.attempts if a.error is not None]
    assert len(errored) == 1
    assert "connection reset" in errored[0].error
    assert errored[0].success_marker_found is False
    # Two marker-bearing responses succeeded; the errored attempt did not count.
    assert result.success_count == 2
    assert result.likely_race_condition is True


def test_no_marker_treats_any_2xx_as_success():
    with patch(PATCH_TARGET, return_value=_resp(201, "anything at all")):
        result = execute(url="https://example.com/redeem")

    assert result.success_count == 5
    assert result.likely_race_condition is True


def test_no_marker_404_is_not_success():
    with patch(PATCH_TARGET, return_value=_resp(404, "not found")):
        result = execute(url="https://example.com/redeem")

    assert result.success_count == 0
    assert result.likely_race_condition is False


def test_normalize_url():
    assert _normalize_url("example.com") == "https://example.com"
    assert _normalize_url("") == ""
    assert _normalize_url("http://example.com/x") == "http://example.com/x"


def test_parse_omits_body_snippet_and_caps_attempts():
    with patch(PATCH_TARGET, return_value=_resp(200, "body text")):
        raw = execute(url="https://example.com/redeem", request_count=20)

    summary = parse(raw)
    assert len(summary["attempts"]) == 10
    assert summary["omitted_attempts"] == 10
    assert "10 more attempts omitted" in summary["note"]
    assert "read_evidence" in summary["note"]
    for a in summary["attempts"]:
        assert "body_snippet" not in a
        assert set(a) == {"index", "status_code", "success_marker_found", "duration_seconds", "error"}

