from __future__ import annotations

from unittest.mock import patch

import pytest

from tradecraft.adapters.http_request.execute import METRICS_DELIMITER
from tradecraft.tools.http_request import HttpRequest


class TestHttpRequestTool:
    @pytest.fixture
    def tool(self):
        return HttpRequest()

    def test_run_success(self, tool):
        fake_raw = {
            "url": "https://example.com/api",
            "method": "POST",
            "stdout": f"\n{METRICS_DELIMITER}\n201\n0.150\nhttps://example.com/api\n",
            "stderr": "",
            "returncode": 0,
            "raw_headers": "HTTP/1.1 201 Created\r\nServer: nginx/1.22\r\nX-Powered-By: Express\r\nContent-Type: application/json\r\n",
            "raw_body": '{"status": "created", "id": 42}',
        }
        with patch("tradecraft.tools.http_request.run_http_request", return_value=fake_raw):
            res = tool.run(
                url="https://example.com/api",
                method="POST",
                headers="Content-Type: application/json",
                data='{"name": "test"}',
            )
            assert res["status_code"] == 201
            assert res["server"] == "nginx/1.22"
            assert res["headers"]["X-Powered-By"] == "Express"
            assert '{"status": "created", "id": 42}' in res["body"]
            assert "_full_evidence" in res
            assert res["_full_evidence"]["raw_body"] == '{"status": "created", "id": 42}'

    def test_run_error(self, tool):
        fake_raw = {
            "url": "https://example.com",
            "method": "GET",
            "error": "curl: (6) Could not resolve host: example.com",
        }
        with patch("tradecraft.tools.http_request.run_http_request", return_value=fake_raw):
            res = tool.run(url="https://example.com")
            assert res["status_code"] == 0
            assert "Could not resolve host" in res["error"]
            assert "_full_evidence" in res

    def test_extract_evidence(self, tool):
        # A non-trivial path disambiguates from the bare host (see
        # evidence_target_from_url) -- otherwise a second fetch to a
        # different path on example.com.br would silently overwrite
        # this one's evidence.
        params = {"url": "https://example.com.br/admin"}
        result = {
            "url": "https://example.com.br/admin",
            "status_code": 403,
            "_full_evidence": {
                "url": "https://example.com.br/admin",
                "raw_body": "Access Denied",
            },
        }
        ev = tool.extract_evidence(params, result)
        assert ev is not None
        canonical, full, aliases = ev
        assert canonical == "example.com.br/admin"
        assert full["raw_body"] == "Access Denied"
        assert aliases == []
        # Peeks, doesn't pop: extract_facts (called after this in the real
        # loop, tradecraft/execution/loop.py) still needs _full_evidence for a
        # batch call to produce a fact for every URL, not just the
        # truncated display subset. The loop itself strips the key before
        # returning to the model, once both extractions are done.
        assert "_full_evidence" in result

    def test_extract_evidence_root_path_stays_bare_host(self, tool):
        params = {"url": "https://example.com.br/"}
        result = {
            "url": "https://example.com.br/",
            "status_code": 200,
            "_full_evidence": {"url": "https://example.com.br/", "raw_body": "home"},
        }
        canonical, _, _aliases = tool.extract_evidence(params, result)
        assert canonical == "example.com.br"

    def test_extract_facts_live_and_tech(self, tool):
        params = {"url": "https://example.com.br/api"}
        result = {
            "status_code": 200,
            "server": "LiteSpeed",
            "headers": {"X-Powered-By": "PHP/7.4.33"},
            "evidence_id": "http_request:example.com.br",
        }
        facts = tool.extract_facts(params, result)
        assert len(facts) == 1
        fact = facts[0]
        assert fact["host"] == "example.com.br"
        assert fact["port"] == 443
        assert fact["live"] is True
        assert fact["web_servers"] == ["LiteSpeed"]
        assert fact["technologies"] == ["PHP/7.4.33"]
        assert fact["evidence"] == "http_request:example.com.br"

    def test_extract_facts_empty_on_dead(self, tool):
        params = {"url": "https://example.com.br/api"}
        result = {
            "status_code": 0,
            "error": "Connection refused",
        }
        facts = tool.extract_facts(params, result)
        assert facts == []


class TestHttpRequestBatch:
    """Confirming the same request shape across several known URLs in one
    call, instead of one sequential http_request call per URL."""

    @pytest.fixture
    def tool(self):
        return HttpRequest()

    def test_run_many_urls_returns_one_result_per_url(self, tool):
        fakes = {
            "https://a.example.com/v1/products": {
                "url": "https://a.example.com/v1/products", "method": "GET",
                "stdout": f"\n{METRICS_DELIMITER}\n401\n0.05\nhttps://a.example.com/v1/products\n",
                "stderr": "", "returncode": 0,
                "raw_headers": "HTTP/1.1 401 Unauthorized\r\n", "raw_body": "no auth",
            },
            "https://a.example.com/v1/payments": {
                "url": "https://a.example.com/v1/payments", "method": "GET",
                "stdout": f"\n{METRICS_DELIMITER}\n404\n0.05\nhttps://a.example.com/v1/payments\n",
                "stderr": "", "returncode": 0,
                "raw_headers": "HTTP/1.1 404 Not Found\r\n", "raw_body": "missing",
            },
        }
        with patch("tradecraft.tools.http_request.run_http_request", side_effect=lambda url, **kw: fakes[url]):
            res = tool.run(url="https://a.example.com/v1/products,https://a.example.com/v1/payments")

        assert res["requested_count"] == 2
        assert len(res["results"]) == 2
        assert res["results"][0]["status_code"] == 401
        assert res["results"][1]["status_code"] == 404
        assert "_full_evidence" in res
        assert len(res["_full_evidence"]["results"]) == 2

    def test_run_many_urls_truncates_past_cap_and_notes_it(self, tool):
        urls = [f"https://a.example.com/v1/r{i}" for i in range(20)]
        fake = lambda url, **kw: {
            "url": url, "method": "GET",
            "stdout": f"\n{METRICS_DELIMITER}\n200\n0.01\n{url}\n",
            "stderr": "", "returncode": 0, "raw_headers": "HTTP/1.1 200 OK\r\n", "raw_body": "ok",
        }
        with patch("tradecraft.tools.http_request.run_http_request", side_effect=fake):
            res = tool.run(url=",".join(urls))

        assert res["requested_count"] == 20
        assert len(res["results"]) == 15
        assert res["omitted_results"] == 5
        assert "more requested URLs omitted" in res["note"]

    def test_run_many_urls_flags_when_all_requests_timed_out(self, tool):
        # Real captured case (example.com): the model batched .git/HEAD,
        # manifest.json, and wp-login.php in one call after the shared host
        # started rate-limiting it; all 3 came back status_code=0/curl timeout,
        # and the report's "Verified Clean" section read that as a negative
        # result instead of "never got an answer."
        urls = [
            "https://example.com/.git/HEAD",
            "https://example.com/manifest.json",
            "https://example.com/wp-login.php",
        ]
        fake = lambda url, **kw: {
            "url": url, "method": "GET",
            "error": "curl: (28) Connection timed out after 10000 milliseconds",
        }
        with patch("tradecraft.tools.http_request.run_http_request", side_effect=fake):
            res = tool.run(url=",".join(urls))

        assert res["requested_count"] == 3
        assert res["succeeded_count"] == 0
        assert res["failed_count"] == 3
        assert all(r["status_code"] == 0 for r in res["results"])
        assert "untested, not as a clean negative result" in res["warning"]

    def test_run_many_urls_no_warning_when_all_succeed(self, tool):
        fakes = {
            "https://a.example.com/v1/products": {
                "url": "https://a.example.com/v1/products", "method": "GET",
                "stdout": f"\n{METRICS_DELIMITER}\n401\n0.05\nhttps://a.example.com/v1/products\n",
                "stderr": "", "returncode": 0,
                "raw_headers": "HTTP/1.1 401 Unauthorized\r\n", "raw_body": "no auth",
            },
            "https://a.example.com/v1/payments": {
                "url": "https://a.example.com/v1/payments", "method": "GET",
                "stdout": f"\n{METRICS_DELIMITER}\n404\n0.05\nhttps://a.example.com/v1/payments\n",
                "stderr": "", "returncode": 0,
                "raw_headers": "HTTP/1.1 404 Not Found\r\n", "raw_body": "missing",
            },
        }
        with patch("tradecraft.tools.http_request.run_http_request", side_effect=lambda url, **kw: fakes[url]):
            res = tool.run(url="https://a.example.com/v1/products,https://a.example.com/v1/payments")

        assert res["succeeded_count"] == 2
        assert res["failed_count"] == 0
        assert "warning" not in res

    def test_extract_facts_from_batch_results(self, tool):
        # Both entries land on the same (host, port) -- status_code 401 is
        # "live"-shaped and 404 isn't, but both carry the batch's shared
        # evidence pointer, so FactStore.merge_port (not this method) is
        # what collapses them into a single record.
        params = {"url": "https://a.example.com/v1/products,https://a.example.com/v1/payments"}
        result = {
            "results": [
                {"url": "https://a.example.com/v1/products", "status_code": 401},
                {"url": "https://a.example.com/v1/payments", "status_code": 404},
            ],
            "evidence_id": "http_request:a.example.com/v1/products",
        }
        facts = tool.extract_facts(params, result)
        assert len(facts) == 2
        assert all(f["host"] == "a.example.com" and f["port"] == 443 for f in facts)
        assert facts[0]["live"] is True
        assert "live" not in facts[1]
        assert all(f["evidence"] == "http_request:a.example.com/v1/products" for f in facts)

    def test_extract_facts_uses_full_evidence_to_cover_urls_past_truncation(self, tool):
        # Mirrors a real run_consecutive_scope.sh engagement: http_request
        # truncates its displayed "results" to BATCH_RESULT_CAP, but every
        # requested URL still needs its own fact row (with its own
        # evidence pointer) or it's silently invisible in Known Facts even
        # though its full response is sitting in the evidence store.
        urls = [f"https://a.example.com/v1/r{i}" for i in range(20)]
        full_results = [
            {"url": u, "status_code": 200, "server": "nginx", "headers": {}}
            for u in urls
        ]
        params = {"url": ",".join(urls)}
        result = {
            "results": full_results[:15],
            "omitted_results": 5,
            "_full_evidence": {"target": params["url"], "results": full_results},
            "evidence_id": "http_request:a.example.com/v1/r0",
        }
        facts = tool.extract_facts(params, result)
        assert len(facts) == 20
        assert facts[19]["host"] == "a.example.com"
        assert facts[19]["web_servers"] == ["nginx"]
        assert facts[19]["evidence"] == "http_request:a.example.com/v1/r0"

    def test_extract_evidence_batch_keys_off_first_url(self, tool):
        params = {"url": "https://a.example.com/v1/products,https://a.example.com/v1/payments"}
        result = {"_full_evidence": {"target": params["url"], "results": []}}
        canonical, full, aliases = tool.extract_evidence(params, result)
        assert canonical == "a.example.com/v1/products"
        assert full["results"] == []
        # Regression: every other URL in the batch must be registered as
        # an alias, or read_evidence on it will always report "not found"
        # even once real data exists -- see EvidenceStore.save()'s docstring.
        assert aliases == ["a.example.com/v1/payments"]


class TestHttpRequestBodyPaging:
    @pytest.fixture
    def tool(self):
        return HttpRequest()

    @staticmethod
    def _raw(body: str) -> dict:
        return {
            "url": "https://example.com/big",
            "method": "GET",
            "stdout": f"\n{METRICS_DELIMITER}\n200\n0.100\nhttps://example.com/big\n",
            "stderr": "", "returncode": 0,
            "raw_headers": "HTTP/1.1 200 OK\r\n",
            "raw_body": body,
        }

    def test_body_offset_and_chars_are_applied(self, tool):
        body = "0123456789" * 100  # 1000 chars
        with patch("tradecraft.tools.http_request.run_http_request", return_value=self._raw(body)):
            res = tool.run(url="https://example.com/big", body_offset=100, body_chars=50)
        assert res["body_offset"] == 100
        assert res["next_body_offset"] == 150
        assert res["body"].startswith(body[100:150])
        assert res["body_truncated"] is True

    def test_body_chars_is_capped_per_call(self, tool):
        body = "x" * 20000
        with patch("tradecraft.tools.http_request.run_http_request", return_value=self._raw(body)):
            res = tool.run(url="https://example.com/big", body_chars=10**6)
        assert res["body"].startswith("x" * 8000)
        assert not res["body"].startswith("x" * 8001)
        assert res["next_body_offset"] == 8000

    def test_default_call_still_returns_2000_chars(self, tool):
        body = "y" * 5000
        with patch("tradecraft.tools.http_request.run_http_request", return_value=self._raw(body)):
            res = tool.run(url="https://example.com/big")
        assert res["body"].startswith("y" * 2000)
        assert res["next_body_offset"] == 2000
        assert res["body_length"] == 5000

    def test_full_evidence_still_stores_whole_body(self, tool):
        body = "z" * 5000
        with patch("tradecraft.tools.http_request.run_http_request", return_value=self._raw(body)):
            res = tool.run(url="https://example.com/big", body_offset=4000, body_chars=500)
        assert res["_full_evidence"]["raw_body"] == body
