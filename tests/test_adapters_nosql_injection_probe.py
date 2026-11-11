"""
Adapter-level tests for nosql_injection_probe: argv/body construction via a
mocked requests.post, and pure is_anomalous() differential logic.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
import requests

from tradecraft.adapters.nosql_injection_probe.execute import (
    MAX_PAYLOADS,
    NOSQL_OPERATORS,
    RawNoSqlInjectionResult,
    RawNoSqlResponse,
    execute,
)
from tradecraft.adapters.nosql_injection_probe.parse import is_anomalous, parse

PATCH_POST = "tradecraft.adapters.nosql_injection_probe.execute.requests.post"
TARGET = "https://example.com/api/login"
BODY = '{"username": "alice", "password": "secret"}'


def _mock_resp(status: int, text: str) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.text = text
    resp.headers = {"content-type": "application/json"}
    return resp


def _raw(status: int, length: int, operator: str = "x") -> RawNoSqlResponse:
    return RawNoSqlResponse(operator=operator, status_code=status, body_length=length)


class TestExecuteAndParse:
    def test_anomaly_detected_on_ne_operator(self):
        baseline = _mock_resp(401, '{"error":"invalid credentials"}')
        ne_hit = _mock_resp(200, '{"token":"abc123","user":{"id":1}}')
        other = _mock_resp(401, '{"error":"invalid credentials"}')

        # First call is baseline, second is the $ne variant, rest are unchanged.
        side_effects = [baseline, ne_hit] + [other] * (MAX_PAYLOADS - 1)
        with patch(PATCH_POST, side_effect=side_effects) as mock_post:
            raw = execute(target=TARGET, body=BODY, field="username")

        assert raw.error is None
        assert mock_post.call_count == 1 + MAX_PAYLOADS
        # Baseline sends original body; the $ne probe replaces the field value.
        assert mock_post.call_args_list[0].kwargs["json"] == {"username": "alice", "password": "secret"}
        assert mock_post.call_args_list[1].kwargs["json"] == {"username": {"$ne": None}, "password": "secret"}

        assert is_anomalous(raw.baseline_response, raw.probes[0]) is True

        out = parse(raw)
        assert out["vulnerable"] is True
        assert "$ne" in out["anomalous_operators"]
        assert out["baseline_status"] == 401
        assert out["tested_operators"] == [op for op, _ in NOSQL_OPERATORS[:MAX_PAYLOADS]]

    def test_no_anomaly_when_all_responses_identical(self):
        same = _mock_resp(401, '{"error":"invalid credentials"}')
        with patch(PATCH_POST, return_value=same):
            raw = execute(target=TARGET, body=BODY, field="username")

        out = parse(raw)
        assert out["vulnerable"] is False
        assert out["anomalous_operators"] == []

    def test_invalid_json_body(self):
        with patch(PATCH_POST) as mock_post:
            raw = execute(target=TARGET, body="not json", field="username")
        assert "not valid JSON" in raw.error
        mock_post.assert_not_called()

    def test_field_not_in_body(self):
        with patch(PATCH_POST) as mock_post:
            raw = execute(target=TARGET, body='{"other": "x"}', field="username")
        assert "not found" in raw.error
        mock_post.assert_not_called()

    def test_baseline_request_exception_does_not_stop_probes(self):
        ok = _mock_resp(401, '{"error":"invalid credentials"}')
        side_effects = [requests.RequestException("boom")] + [ok] * MAX_PAYLOADS
        with patch(PATCH_POST, side_effect=side_effects) as mock_post:
            raw = execute(target=TARGET, body=BODY, field="username")

        assert raw.baseline_response.error == "boom"
        assert mock_post.call_count == 1 + MAX_PAYLOADS
        assert all(p.error is None for p in raw.probes)
        assert len(raw.probes) == MAX_PAYLOADS

    def test_probe_request_exception_is_isolated(self):
        ok = _mock_resp(401, '{"error":"invalid credentials"}')
        side_effects = [ok, requests.RequestException("timeout")] + [ok] * (MAX_PAYLOADS - 1)
        with patch(PATCH_POST, side_effect=side_effects):
            raw = execute(target=TARGET, body=BODY, field="username")

        assert raw.probes[0].error == "timeout"
        assert all(p.error is None for p in raw.probes[1:])
        assert parse(raw)["vulnerable"] is False

    def test_custom_headers_are_parsed_and_sent(self):
        ok = _mock_resp(401, "x")
        with patch(PATCH_POST, return_value=ok) as mock_post:
            execute(
                target=TARGET,
                body=BODY,
                field="username",
                headers="Authorization: Bearer tok\nCookie: session=xyz",
            )
        sent = mock_post.call_args_list[0].kwargs["headers"]
        assert sent["Authorization"] == "Bearer tok"
        assert sent["Cookie"] == "session=xyz"
        assert sent["Content-Type"] == "application/json"

    def test_hard_cap_on_variants(self):
        assert MAX_PAYLOADS == 6
        ok = _mock_resp(401, "x")
        with patch(PATCH_POST, return_value=ok) as mock_post:
            execute(target=TARGET, body=BODY, field="username")
        assert mock_post.call_count == 1 + MAX_PAYLOADS


class TestIsAnomalous:
    def test_same_status_similar_length_is_not_anomalous(self):
        assert is_anomalous(_raw(401, 100), _raw(401, 102)) is False

    def test_2xx_vs_non_2xx_is_anomalous_regardless_of_length(self):
        assert is_anomalous(_raw(401, 100), _raw(200, 100)) is True
        assert is_anomalous(_raw(200, 100), _raw(403, 100)) is True

    def test_different_status_and_length_delta_over_5_is_anomalous(self):
        assert is_anomalous(_raw(404, 100), _raw(500, 200)) is True

    def test_different_status_but_small_length_delta_is_not_anomalous(self):
        assert is_anomalous(_raw(404, 100), _raw(500, 103)) is False

    def test_errored_probe_is_never_anomalous(self):
        err = RawNoSqlResponse(operator="$ne", error="boom")
        assert is_anomalous(_raw(401, 100), err) is False

    def test_missing_baseline_is_never_anomalous(self):
        assert is_anomalous(None, _raw(200, 100)) is False


def test_parse_top_level_error_passthrough():
    raw = RawNoSqlInjectionResult(target=TARGET, field="username", error="'body' is not valid JSON")
    out = parse(raw)
    assert out["error"] == "'body' is not valid JSON"
    assert "vulnerable" not in out
