from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from tradecraft.adapters.idor_probe.execute import (
    RawHttpResponse,
    RawIdorResult,
    build_url_for_value,
    execute,
    normalize_target_url,
    parse_custom_headers,
    resolve_target_plan,
)
from tradecraft.adapters.idor_probe.parse import (
    classify_probe,
    compute_similarity,
    extract_html_diff,
    extract_json_diff,
    is_soft_404,
    parse_result,
)


class TestTargetResolution:
    def test_normalize_target_url(self):
        assert normalize_target_url("http://test.local/api") == "http://test.local/api"
        assert normalize_target_url("https://test.local/api") == "https://test.local/api"
        assert normalize_target_url("test.local/api") == "https://test.local/api"
        assert normalize_target_url("") == ""

    def test_resolve_query_param_auto_detect(self):
        plan = resolve_target_plan("https://example.com/api/orders?order_id=105")
        assert not plan.error
        assert plan.param_name == "order_id"
        assert plan.baseline_value == "105"
        assert plan.candidate_values == ["106", "104", "1"]
        assert plan.url_template == "https://example.com/api/orders?order_id={ID}"

    def test_resolve_query_param_explicit(self):
        plan = resolve_target_plan(
            "https://example.com/profile?role=user&uid=42",
            param="uid",
        )
        assert not plan.error
        assert plan.param_name == "uid"
        assert plan.baseline_value == "42"
        assert plan.candidate_values == ["43", "41", "1"]
        assert "uid={ID}" in plan.url_template
        assert "role=user" in plan.url_template

    def test_resolve_path_segment_auto_detect(self):
        plan = resolve_target_plan("https://example.com/api/v1/users/500/details")
        assert not plan.error
        assert plan.param_name == "path_segment"
        assert plan.baseline_value == "500"
        assert plan.candidate_values == ["501", "499", "1"]
        assert plan.url_template == "https://example.com/api/v1/users/{ID}/details"

    def test_resolve_explicit_placeholder(self):
        plan = resolve_target_plan(
            "https://example.com/documents/{ID}/download",
            candidate_values="10,20,30,40",
        )
        assert not plan.error
        assert plan.candidate_values == ["10", "20", "30"]  # capped at 3
        assert plan.url_template == "https://example.com/documents/{ID}/download"

    def test_resolve_custom_candidate_values(self):
        plan = resolve_target_plan(
            "https://example.com/items?id=1",
            candidate_values="2,99,admin",
        )
        assert not plan.error
        assert plan.baseline_value == "1"
        assert plan.candidate_values == ["2", "99", "admin"]

    def test_resolve_non_numeric_without_candidates_fails(self):
        plan = resolve_target_plan("https://example.com/users?name=alice")
        assert plan.error
        assert "non-numeric" in plan.error

    def test_resolve_no_identifier_fails(self):
        plan = resolve_target_plan("https://example.com/about/team")
        assert plan.error
        assert "No object identifier found" in plan.error

    def test_build_url_for_value(self):
        template = "https://example.com/items/{ID}?filter=active"
        assert build_url_for_value(template, "105") == "https://example.com/items/105?filter=active"
        assert build_url_for_value(template, "A/B") == "https://example.com/items/A%2FB?filter=active"

    def test_parse_custom_headers(self):
        raw_headers = "Authorization: Bearer token123\nCookie: sess=abc\nInvalidHeader"
        hdrs = parse_custom_headers(raw_headers)
        assert hdrs["Authorization"] == "Bearer token123"
        assert hdrs["Cookie"] == "sess=abc"
        assert "Mozilla" in hdrs["User-Agent"]


class TestDifferentialParsing:
    def test_compute_similarity(self):
        assert compute_similarity("hello world", "hello world") == 1.0
        assert compute_similarity("", "abc") == 0.0
        assert 0.0 < compute_similarity("hello world", "hello world 2") < 1.0

    def test_is_soft_404(self):
        assert not is_soft_404(404, "Not Found", "baseline")  # 404 is hard 404, not soft
        assert is_soft_404(200, '{"error": "Object not found"}', "baseline")
        assert is_soft_404(200, '{"status": "ok", "data": null}', "baseline")
        assert is_soft_404(200, "<p>Registro não encontrado</p>", "baseline")
        assert not is_soft_404(200, '{"data": {"id": 105, "name": "Alice"}}', "baseline")

    def test_extract_json_diff_distinct(self):
        base = json.dumps({"id": 105, "name": "Alice", "email": "alice@corp.local"})
        cand = json.dumps({"id": 106, "name": "Bob", "email": "bob@corp.local"})

        is_json, diff_keys, preview = extract_json_diff(base, cand)
        assert is_json
        assert "id" in diff_keys
        assert "name" in diff_keys
        assert "Bob" in preview
        assert "Alice" in preview

    def test_extract_json_diff_ignores_dynamic_keys(self):
        base = json.dumps({"id": 105, "timestamp": "2026-11-02T10:00:00Z", "csrf": "token1"})
        cand = json.dumps({"id": 105, "timestamp": "2026-11-02T10:00:05Z", "csrf": "token2"})

        is_json, diff_keys, preview = extract_json_diff(base, cand)
        assert is_json
        assert diff_keys == []
        assert preview == ""

    def test_extract_html_diff_strips_boilerplate(self):
        base = (
            "<!DOCTYPE html>\n<html><head><title>Dashboard</title></head>\n"
            "<body>\n<div class='nav'>Home</div>\n"
            "<h1>Pedido #105</h1>\n"
            "<p>Cliente: Alice</p>\n"
            "<footer>Footer info</footer></body></html>"
        )
        cand = (
            "<!DOCTYPE html>\n<html><head><title>Dashboard</title></head>\n"
            "<body>\n<div class='nav'>Home</div>\n"
            "<h1>Pedido #106</h1>\n"
            "<p>Cliente: Bob</p>\n"
            "<footer>Footer info</footer></body></html>"
        )

        unique_lines, preview = extract_html_diff(base, cand)
        assert "<h1>Pedido #106</h1>" in unique_lines
        assert "<p>Cliente: Bob</p>" in unique_lines
        # Shared lines like <title>Dashboard</title> must NOT be in unique lines
        assert "<title>Dashboard</title>" not in unique_lines
        assert "<div class='nav'>Home</div>" not in unique_lines


class TestProbeClassification:
    def test_classify_identical(self):
        base = RawHttpResponse(url="http://x/1", tested_id="1", status_code=200, body="same body")
        probe = RawHttpResponse(url="http://x/2", tested_id="2", status_code=200, body="same body")
        res = classify_probe(probe, base, similarity=1.0, has_meaningful_diff=False, is_soft404=False)
        assert res == "identical"

    def test_classify_distinct_candidate(self):
        base = RawHttpResponse(url="http://x/1", tested_id="1", status_code=200, body="User: Alice")
        probe = RawHttpResponse(url="http://x/2", tested_id="2", status_code=200, body="User: Bob")
        res = classify_probe(probe, base, similarity=0.75, has_meaningful_diff=True, is_soft404=False)
        assert res == "distinct_object_candidate"

    def test_classify_soft_404(self):
        base = RawHttpResponse(url="http://x/1", tested_id="1", status_code=200, body="User: Alice")
        probe = RawHttpResponse(url="http://x/2", tested_id="2", status_code=200, body="Error: Record not found")
        res = classify_probe(probe, base, similarity=0.2, has_meaningful_diff=True, is_soft404=True)
        assert res == "soft_404_or_error"

    def test_classify_not_found(self):
        base = RawHttpResponse(url="http://x/1", tested_id="1", status_code=200, body="User: Alice")
        probe = RawHttpResponse(url="http://x/2", tested_id="2", status_code=404, body="404")
        res = classify_probe(probe, base, similarity=0.1, has_meaningful_diff=False, is_soft404=False)
        assert res == "not_found"

    def test_classify_auth_required(self):
        base = RawHttpResponse(url="http://x/1", tested_id="1", status_code=200, body="User: Alice")
        probe = RawHttpResponse(url="http://x/2", tested_id="2", status_code=403, body="Forbidden")
        res = classify_probe(probe, base, similarity=0.1, has_meaningful_diff=False, is_soft404=False)
        assert res == "auth_required"


class TestExecutionMock:
    @patch("tradecraft.adapters.idor_probe.execute.requests.get")
    def test_execute_and_parse_end_to_end(self, mock_get):
        # Mock baseline
        mock_baseline_resp = MagicMock()
        mock_baseline_resp.url = "https://example.com/api/order?id=105"
        mock_baseline_resp.status_code = 200
        mock_baseline_resp.headers = {"content-type": "application/json"}
        mock_baseline_resp.text = json.dumps({"id": 105, "customer": "Alice", "total": 100})

        mock_probe1 = MagicMock()
        mock_probe1.url = "https://example.com/api/order?id=106"
        mock_probe1.status_code = 200
        mock_probe1.headers = {"content-type": "application/json"}
        mock_probe1.text = json.dumps({"id": 106, "customer": "Bob", "total": 200})

        mock_probe2 = MagicMock()
        mock_probe2.url = "https://example.com/api/order?id=104"
        mock_probe2.status_code = 404
        mock_probe2.headers = {"content-type": "text/html"}
        mock_probe2.text = "Not Found"

        mock_probe3 = MagicMock()
        mock_probe3.url = "https://example.com/api/order?id=1"
        mock_probe3.status_code = 200
        mock_probe3.headers = {"content-type": "application/json"}
        mock_probe3.text = json.dumps({"id": 105, "customer": "Alice", "total": 100})

        mock_get.side_effect = [mock_baseline_resp, mock_probe1, mock_probe2, mock_probe3]

        raw = execute("https://example.com/api/order?id=105")
        assert not raw.error
        assert raw.baseline_id == "105"
        assert len(raw.probes) == 3

        parsed = parse_result(raw)
        assert parsed["target"] == "https://example.com/api/order?id=105"
        assert parsed["param"] == "id"
        assert parsed["potential_idor_detected"] is True
        assert len(parsed["probes"]) == 3

        # Probe 1 should be distinct_object_candidate
        assert parsed["probes"][0]["classification"] == "distinct_object_candidate"
        assert "Bob" in parsed["probes"][0]["diff_preview"]

        # Probe 2 should be not_found
        assert parsed["probes"][1]["classification"] == "not_found"

        # Probe 3 should be identical
        assert parsed["probes"][2]["classification"] == "identical"
