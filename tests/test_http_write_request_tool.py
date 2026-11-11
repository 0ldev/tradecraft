from __future__ import annotations

from unittest.mock import patch

import pytest

from tradecraft.adapters.http_request.execute import METRICS_DELIMITER
from tradecraft.tools.http_write_request import HttpWriteRequest


class TestHttpWriteRequestTool:
    @pytest.fixture
    def tool(self):
        return HttpWriteRequest()

    def test_run_success_put(self, tool):
        fake_raw = {
            "url": "http://bucket.s3.amazonaws.com/probe.txt",
            "method": "PUT",
            "stdout": f"\n{METRICS_DELIMITER}\n200\n0.150\nhttp://bucket.s3.amazonaws.com/probe.txt\n",
            "stderr": "",
            "returncode": 0,
            "raw_headers": "HTTP/1.1 200 OK\r\nETag: \"5eb63bbbe01eeed093cb22bb8f5acdc3\"\r\n",
            "raw_body": "",
        }
        with patch("tradecraft.tools.http_write_request.run_http_write_request", return_value=fake_raw):
            res = tool.run(
                url="http://bucket.s3.amazonaws.com/probe.txt",
                method="PUT",
                data="hello",
            )
        assert res["status_code"] == 200
        assert res["headers"]["ETag"] == '"5eb63bbbe01eeed093cb22bb8f5acdc3"'
        assert "_full_evidence" in res

    def test_run_passes_through_adapter_rejection(self, tool):
        # The adapter itself rejects a non-write method -- the tool layer
        # must surface that as an ordinary error result, not raise.
        fake_raw = {
            "url": "https://example.com/obj",
            "method": "GET",
            "error": "method must be one of ['DELETE', 'PATCH', 'PUT'] -- "
                     "http_write_request only performs state-mutating writes/deletes. "
                     "Use http_request for GET, HEAD, OPTIONS, or POST.",
        }
        with patch("tradecraft.tools.http_write_request.run_http_write_request", return_value=fake_raw):
            res = tool.run(url="https://example.com/obj", method="GET")
        assert res["status_code"] == 0
        assert "http_request" in res["error"]

    def test_run_error_connection(self, tool):
        fake_raw = {
            "url": "https://example.com/obj",
            "method": "DELETE",
            "error": "curl: (6) Could not resolve host: example.com",
        }
        with patch("tradecraft.tools.http_write_request.run_http_write_request", return_value=fake_raw):
            res = tool.run(url="https://example.com/obj", method="DELETE")
        assert res["status_code"] == 0
        assert "Could not resolve host" in res["error"]
        assert "_full_evidence" in res

    def test_extract_evidence(self, tool):
        params = {"url": "https://example.com.br/objects/probe.txt"}
        result = {
            "url": "https://example.com.br/objects/probe.txt",
            "status_code": 200,
            "_full_evidence": {
                "url": "https://example.com.br/objects/probe.txt",
                "raw_body": "",
            },
        }
        ev = tool.extract_evidence(params, result)
        assert ev is not None
        canonical, full, aliases = ev
        assert canonical == "example.com.br/objects/probe.txt"
        assert full["raw_body"] == ""
        assert aliases == []
        assert "_full_evidence" not in result

    def test_extract_evidence_none_without_full_evidence(self, tool):
        params = {"url": "https://example.com/obj"}
        result = {"status_code": 200}
        assert tool.extract_evidence(params, result) is None

    def test_extract_facts_live_write_succeeded(self, tool):
        params = {"url": "https://example.com.br/objects/probe.txt"}
        result = {
            "status_code": 200,
            "evidence_id": "http_write_request:example.com.br/objects/probe.txt",
        }
        facts = tool.extract_facts(params, result)
        assert len(facts) == 1
        fact = facts[0]
        assert fact["host"] == "example.com.br"
        assert fact["port"] == 443
        assert fact["live"] is True
        assert fact["evidence"] == "http_write_request:example.com.br/objects/probe.txt"

    def test_extract_facts_empty_on_dead(self, tool):
        params = {"url": "https://example.com.br/objects/probe.txt"}
        result = {"status_code": 0, "error": "Connection refused"}
        facts = tool.extract_facts(params, result)
        assert facts == []

    def test_extract_facts_empty_without_url(self, tool):
        assert tool.extract_facts({}, {"status_code": 200}) == []
