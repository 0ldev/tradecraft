from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from tradecraft.adapters.http_request.execute import (
    ALLOWED_METHODS,
    METRICS_DELIMITER,
    build_argv,
    execute,
    execute_unchecked,
    normalize_target_url,
    normalize_urls,
)
from tradecraft.adapters.http_request.parse import (
    evidence_target_from_url,
    host_port_from_url,
    parse_curl_headers,
    parse_http_response,
)


class TestHttpRequestExecute:
    def test_normalize_target_url(self):
        assert normalize_target_url("") == ""
        assert normalize_target_url("  ") == ""
        assert normalize_target_url("example.com") == "https://example.com"
        assert normalize_target_url("http://example.com/foo") == "http://example.com/foo"
        assert normalize_target_url("https://example.com:8443/bar") == "https://example.com:8443/bar"

    def test_build_argv_default(self):
        argv = build_argv(url="https://example.com")
        assert argv[0] == "curl"
        assert "-s" in argv
        assert "-S" in argv
        assert "-k" in argv
        assert "-X" in argv
        assert argv[argv.index("-X") + 1] == "GET"
        assert "--max-time" in argv
        assert "-L" not in argv
        assert argv[-1] == "https://example.com"

    def test_build_argv_custom(self):
        argv = build_argv(
            url="example.com/api",
            method="POST",
            headers="Authorization: Bearer 12345\nContent-Type: application/json",
            data='{"key": "value"}',
            follow_redirects=True,
            timeout=15,
            header_file="/tmp/h.txt",
            body_file="/tmp/b.txt",
        )
        assert "-X" in argv
        assert argv[argv.index("-X") + 1] == "POST"
        assert "-L" in argv
        assert "-H" in argv
        assert "Authorization: Bearer 12345" in argv
        assert "Content-Type: application/json" in argv
        assert "-d" in argv
        assert argv[argv.index("-d") + 1] == '{"key": "value"}'
        assert "-D" in argv
        assert argv[argv.index("-D") + 1] == "/tmp/h.txt"
        assert "-o" in argv
        assert argv[argv.index("-o") + 1] == "/tmp/b.txt"
        assert argv[argv.index("--max-time") + 1] == "15"
        assert argv[-1] == "https://example.com/api"

    def test_execute_empty_url(self):
        res = execute(url="")
        assert "error" in res
        assert "empty url" in res["error"]

    def test_execute_missing_binary(self):
        with patch("shutil.which", return_value=None):
            res = execute(url="https://example.com", binary="nonexistent_curl")
            assert "error" in res
            assert "not found on PATH" in res["error"]

    def test_execute_timeout(self):
        with patch("shutil.which", return_value="/bin/curl"), \
             patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["curl"], timeout=5)):
            res = execute(url="https://example.com", timeout=5)
            assert "error" in res
            assert "timed out after 5s" in res["error"]

    def test_execute_success(self):
        fake_stdout = f"\n{METRICS_DELIMITER}\n200\n0.123\nhttps://example.com/\n"
        fake_proc = MagicMock(returncode=0, stdout=fake_stdout, stderr="")
        with patch("shutil.which", return_value="/bin/curl"), \
             patch("subprocess.run", return_value=fake_proc), \
             patch("pathlib.Path.read_text", side_effect=["HTTP/1.1 200 OK\nServer: nginx\n", "Hello World"]):
            with patch("os.path.exists", return_value=True):
                res = execute(url="https://example.com")
                assert res["returncode"] == 0
                assert res["raw_headers"] == "HTTP/1.1 200 OK\nServer: nginx\n"
                assert res["raw_body"] == "Hello World"
                assert METRICS_DELIMITER in res["stdout"]


class TestHttpRequestMethodAllowlist:
    """http_request is the always-available, non-destructive tool: it must
    reject state-mutating writes/deletes (PUT/DELETE/PATCH) and point to
    the destructive http_write_request tool instead -- see
    tradecraft/adapters/http_write_request/ and docs/policy.md."""

    def test_allowed_methods_is_exactly_get_head_options_post(self):
        assert ALLOWED_METHODS == {"GET", "HEAD", "OPTIONS", "POST"}

    @pytest.mark.parametrize("method", ["PUT", "DELETE", "PATCH", "put", "delete"])
    def test_write_methods_are_rejected(self, method):
        res = execute(url="https://example.com/obj", method=method)
        assert "error" in res
        assert "http_write_request" in res["error"]
        assert res["method"] == method.strip().upper()

    def test_rejected_write_never_invokes_curl(self):
        with patch("subprocess.run") as mock_run:
            execute(url="https://example.com/obj", method="PUT")
            mock_run.assert_not_called()

    @pytest.mark.parametrize("method", ["GET", "HEAD", "OPTIONS", "POST", "get", ""])
    def test_safe_methods_still_reach_curl(self, method):
        fake_stdout = f"\n{METRICS_DELIMITER}\n200\n0.1\nhttps://example.com/\n"
        fake_proc = MagicMock(returncode=0, stdout=fake_stdout, stderr="")
        with patch("shutil.which", return_value="/bin/curl"), \
             patch("subprocess.run", return_value=fake_proc), \
             patch("os.path.exists", return_value=True), \
             patch("pathlib.Path.read_text", side_effect=["HTTP/1.1 200 OK\r\n", "ok"]):
            res = execute(url="https://example.com", method=method)
        assert "error" not in res

    def test_execute_unchecked_has_no_allowlist_of_its_own(self):
        # execute_unchecked is the shared subprocess runner both
        # http_request's and http_write_request's execute() call after
        # validating method themselves -- it must not re-reject PUT.
        fake_stdout = f"\n{METRICS_DELIMITER}\n200\n0.1\nhttps://example.com/\n"
        fake_proc = MagicMock(returncode=0, stdout=fake_stdout, stderr="")
        with patch("shutil.which", return_value="/bin/curl"), \
             patch("subprocess.run", return_value=fake_proc), \
             patch("os.path.exists", return_value=True), \
             patch("pathlib.Path.read_text", side_effect=["HTTP/1.1 200 OK\r\n", "ok"]):
            res = execute_unchecked(url="https://example.com", method="PUT")
        assert "error" not in res
        assert res["method"] == "PUT"


class TestNormalizeUrls:
    def test_comma_split_dedupes_and_trims(self):
        urls = "https://a.com/x, https://b.com/y ,https://a.com/x,  "
        assert normalize_urls(urls) == ["https://a.com/x", "https://b.com/y"]

    def test_single_url_unaffected(self):
        assert normalize_urls("https://example.com") == ["https://example.com"]

    def test_empty_is_empty(self):
        assert normalize_urls("") == []


class TestHttpRequestParse:
    def test_host_port_from_url(self):
        assert host_port_from_url("https://example.com/foo") == ("example.com", 443)
        assert host_port_from_url("http://example.com/foo") == ("example.com", 80)
        assert host_port_from_url("http://example.com:8080/foo") == ("example.com", 8080)
        assert host_port_from_url("example.com") == ("example.com", 443)
        assert host_port_from_url("") == ("", 80)

    def test_evidence_target_from_url_bare_host_for_trivial_path(self):
        assert evidence_target_from_url("https://example.com") == "example.com"
        assert evidence_target_from_url("https://example.com/") == "example.com"
        assert evidence_target_from_url("example.com") == "example.com"
        assert evidence_target_from_url("") == ""

    def test_evidence_target_from_url_disambiguates_distinct_paths(self):
        """The real bug: two distinct resources on the same host must not
        collapse onto the same evidence target."""
        first = evidence_target_from_url("https://dashboard.example.app/_next/static/chunk1.js")
        second = evidence_target_from_url("https://dashboard.example.app/_next/static/chunk2.js")
        assert first != second
        assert first.startswith("dashboard.example.app")
        assert second.startswith("dashboard.example.app")

    def test_parse_curl_headers(self):
        raw = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: Apache\r\n"
        headers = parse_curl_headers(raw)
        assert headers["Content-Type"] == "text/html"
        assert headers["Server"] == "Apache"

    def test_parse_curl_headers_with_redirect(self):
        raw = (
            "HTTP/1.1 301 Moved Permanently\r\nLocation: /new\r\n\r\n"
            "HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: application/json\r\n"
        )
        headers = parse_curl_headers(raw)
        assert headers["Server"] == "nginx"
        assert headers["Content-Type"] == "application/json"
        assert "Location" not in headers

    def test_parse_http_response_success(self):
        raw_result = {
            "url": "https://example.com",
            "method": "GET",
            "stdout": f"\n{METRICS_DELIMITER}\n200\n0.345\nhttps://example.com/final\n",
            "stderr": "",
            "returncode": 0,
            "raw_headers": "HTTP/2 200\r\nServer: cloudflare\r\nContent-Type: text/html; charset=UTF-8\r\n",
            "raw_body": "<html><body>Hello</body></html>",
        }
        parsed = parse_http_response(raw_result)
        assert parsed["status_code"] == 200
        assert parsed["duration_seconds"] == 0.345
        assert parsed["effective_url"] == "https://example.com/final"
        assert parsed["server"] == "cloudflare"
        assert parsed["content_type"] == "text/html; charset=UTF-8"
        assert parsed["body_length"] == len("<html><body>Hello</body></html>")
        assert not parsed["body_truncated"]
        assert parsed["body"] == "<html><body>Hello</body></html>"

    def test_parse_http_response_truncation(self):
        long_body = "A" * 3000
        raw_result = {
            "url": "https://example.com",
            "method": "POST",
            "stdout": f"\n{METRICS_DELIMITER}\n200\n0.100\nhttps://example.com\n",
            "returncode": 0,
            "raw_headers": "HTTP/1.1 200 OK\r\n",
            "raw_body": long_body,
        }
        parsed = parse_http_response(raw_result, max_body_chars=500)
        assert parsed["body_truncated"]
        assert parsed["body_length"] == 3000
        assert len(parsed["body"]) > 500
        assert "[showing chars 0-500 of 3000; pass body_offset=500 for the next chunk, or read_evidence(target='example.com', tool_id='http_request') for the full body]" in parsed["body"]
        assert parsed["next_body_offset"] == 500
        assert parsed["body_offset"] == 0

    def _raw_with_body(self, body: str) -> dict:
        return {
            "url": "https://example.com/page",
            "method": "GET",
            "stdout": f"\n{METRICS_DELIMITER}\n200\n0.100\nhttps://example.com/page\n",
            "returncode": 0,
            "raw_headers": "HTTP/1.1 200 OK\r\n",
            "raw_body": body,
        }

    def test_parse_http_response_pages_through_body(self):
        body = "".join(str(i % 10) for i in range(2500))
        raw = self._raw_with_body(body)
        chunks = []
        offset = 0
        while offset is not None:
            parsed = parse_http_response(raw, max_body_chars=1000, body_offset=offset)
            assert parsed["body_offset"] == offset
            chunk_text = parsed["body"].split("\n... [showing")[0]
            chunks.append(chunk_text)
            offset = parsed["next_body_offset"]
        assert "".join(chunks) == body
        assert len(chunks) == 3

    def test_parse_http_response_last_chunk_not_truncated(self):
        raw = self._raw_with_body("x" * 1200)
        parsed = parse_http_response(raw, max_body_chars=1000, body_offset=1000)
        assert parsed["body"] == "x" * 200
        assert not parsed["body_truncated"]
        assert parsed["next_body_offset"] is None

    def test_parse_http_response_offset_past_end_is_clamped(self):
        raw = self._raw_with_body("abc")
        parsed = parse_http_response(raw, max_body_chars=10, body_offset=999)
        assert parsed["body_offset"] == 3
        assert parsed["body"] == ""
        assert not parsed["body_truncated"]

    def test_parse_http_response_truncation_points_at_path_qualified_target(self):
        long_body = "A" * 3000
        raw_result = {
            "url": "https://dashboard.example.app/_next/static/chunk1.js",
            "method": "GET",
            "stdout": f"\n{METRICS_DELIMITER}\n200\n0.100\nhttps://dashboard.example.app/_next/static/chunk1.js\n",
            "returncode": 0,
            "raw_headers": "HTTP/1.1 200 OK\r\n",
            "raw_body": long_body,
        }
        parsed = parse_http_response(raw_result, max_body_chars=500)
        assert "target='dashboard.example.app/_next/static/chunk1.js'" in parsed["body"]

    def test_parse_http_response_error(self):
        raw_result = {
            "url": "https://example.com",
            "method": "GET",
            "error": "request timed out after 10s",
        }
        parsed = parse_http_response(raw_result)
        assert parsed["status_code"] == 0
        assert parsed["error"] == "request timed out after 10s"
