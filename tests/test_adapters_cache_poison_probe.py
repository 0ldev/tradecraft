from unittest.mock import MagicMock, patch
import requests

from tradecraft.adapters.cache_poison_probe import execute as cp_execute
from tradecraft.adapters.cache_poison_probe import parse as cp_parse
from tradecraft.adapters.cache_poison_probe.execute import PoisonAttempt, UNKEYED_HEADERS


def test_build_probe_url():
    url = "https://example.com/item?id=123"
    probe = cp_execute.build_probe_url(url, "cp123456789012")
    assert "https://example.com/item?" in probe
    assert "id=123" in probe
    assert "_cbust=cp123456789012" in probe

    # Defaults to https if missing
    bare = cp_execute.build_probe_url("example.com/test", "cpmarker")
    assert bare.startswith("https://example.com/test?")
    assert "_cbust=cpmarker" in bare


def test_attempt_header_not_reflected():
    # Poison response 200 but marker not in text -> does not attempt clean
    mock_resp = MagicMock(status_code=200, text="<html>hello world</html>")
    with patch("requests.get", return_value=mock_resp) as mock_get:
        attempt = cp_execute.attempt_header("https://example.com", "X-Forwarded-Host")
        assert attempt.attempted_clean is False
        assert attempt.poison_status == 200
        assert mock_get.call_count == 1


def test_attempt_header_poison_500_error():
    mock_resp = MagicMock(status_code=500, text="Internal Server Error")
    with patch("requests.get", return_value=mock_resp) as mock_get:
        attempt = cp_execute.attempt_header("https://example.com", "X-Forwarded-Host")
        assert attempt.attempted_clean is False
        assert attempt.poison_status == 500
        assert mock_get.call_count == 1


def test_attempt_header_poison_request_exception():
    with patch("requests.get", side_effect=requests.RequestException("connection failed")):
        attempt = cp_execute.attempt_header("https://example.com", "X-Forwarded-Host")
        assert attempt.error is not None
        assert "connection failed" in attempt.error
        assert attempt.attempted_clean is False


def test_attempt_header_leaks_into_clean():
    # Capture marker value from first call
    def fake_requests_get(url, headers=None, **kwargs):
        if headers and "X-Forwarded-Host" in headers:
            marker = headers["X-Forwarded-Host"]
            return MagicMock(status_code=200, text=f"<meta property='og:url' content='https://{marker}/'>")
        # Clean request (no headers) receives cached poisoned content
        return MagicMock(status_code=200, text="<meta property='og:url' content='https://cpfake.attacker-controlled.test/'>")

    with patch("requests.get", side_effect=fake_requests_get) as mock_get:
        # Patch random to return fixed marker
        with patch("random.choices", return_value=list("fake")):
            attempt = cp_execute.attempt_header("https://example.com", "X-Forwarded-Host")
            assert attempt.attempted_clean is True
            assert attempt.poison_status == 200
            assert attempt.clean_status == 200
            assert "cpfake.attacker-controlled.test" in attempt.clean_body
            assert mock_get.call_count == 2


def test_execute_checks_all_headers():
    with patch("tradecraft.adapters.cache_poison_probe.execute.attempt_header") as mock_attempt:
        mock_attempt.side_effect = [
            PoisonAttempt(header_name=h, marker_value="m") for h in UNKEYED_HEADERS
        ]
        results = cp_execute.execute("https://example.com")
        assert len(results) == len(UNKEYED_HEADERS)
        assert mock_attempt.call_count == len(UNKEYED_HEADERS)


def test_parse_attempt_and_parse_all():
    long_body = "x" * 600 + "cp123.attacker-controlled.test"
    a_vuln = PoisonAttempt(
        header_name="X-Forwarded-Host",
        marker_value="cp123.attacker-controlled.test",
        poison_status=200,
        poison_body="reflected",
        clean_status=200,
        clean_body=long_body,
        attempted_clean=True,
    )
    res_vuln = cp_parse.parse_attempt(a_vuln)
    assert res_vuln["vulnerable"] is True
    assert len(res_vuln["evidence"]) <= 500  # Snippet truncated

    a_safe = PoisonAttempt(
        header_name="X-Host",
        marker_value="cp456.attacker-controlled.test",
        poison_status=200,
        poison_body="clean",
        clean_status=200,
        clean_body="clean",
        attempted_clean=True,
    )
    res_safe = cp_parse.parse_attempt(a_safe)
    assert res_safe["vulnerable"] is False

    all_res = cp_parse.parse_all([a_vuln, a_safe])
    assert all_res["vulnerable"] is True
    assert all_res["vulnerable_headers"] == ["X-Forwarded-Host"]
    assert len(all_res["attempts"]) == 2
