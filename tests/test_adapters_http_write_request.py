from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from tradecraft.adapters.http_request.execute import METRICS_DELIMITER
from tradecraft.adapters.http_write_request.execute import WRITE_METHODS, execute
from tradecraft.adapters.http_write_request.parse import (
    evidence_target_from_url,
    host_port_from_url,
    parse_http_response,
)


class TestHttpWriteRequestMethodAllowlist:
    def test_put_is_allowed(self):
        fake_stdout = f"\n{METRICS_DELIMITER}\n200\n0.1\nhttps://example.com/obj\n"
        fake_proc = MagicMock(returncode=0, stdout=fake_stdout, stderr="")
        with patch("shutil.which", return_value="/bin/curl"), \
             patch("subprocess.run", return_value=fake_proc), \
             patch("os.path.exists", return_value=True), \
             patch("pathlib.Path.read_text", side_effect=["HTTP/1.1 200 OK\r\n", "ok"]):
            res = execute(url="https://example.com/obj", method="PUT", data="hello")
        assert "error" not in res
        assert res["method"] == "PUT"

    def test_delete_is_allowed(self):
        fake_stdout = f"\n{METRICS_DELIMITER}\n204\n0.1\nhttps://example.com/obj\n"
        fake_proc = MagicMock(returncode=0, stdout=fake_stdout, stderr="")
        with patch("shutil.which", return_value="/bin/curl"), \
             patch("subprocess.run", return_value=fake_proc), \
             patch("os.path.exists", return_value=True), \
             patch("pathlib.Path.read_text", side_effect=["HTTP/1.1 204 No Content\r\n", ""]):
            res = execute(url="https://example.com/obj", method="DELETE")
        assert "error" not in res
        assert res["method"] == "DELETE"

    def test_patch_is_allowed(self):
        fake_stdout = f"\n{METRICS_DELIMITER}\n200\n0.1\nhttps://example.com/obj\n"
        fake_proc = MagicMock(returncode=0, stdout=fake_stdout, stderr="")
        with patch("shutil.which", return_value="/bin/curl"), \
             patch("subprocess.run", return_value=fake_proc), \
             patch("os.path.exists", return_value=True), \
             patch("pathlib.Path.read_text", side_effect=["HTTP/1.1 200 OK\r\n", "ok"]):
            res = execute(url="https://example.com/obj", method="PATCH", data="{}")
        assert "error" not in res
        assert res["method"] == "PATCH"

    def test_get_is_rejected(self):
        res = execute(url="https://example.com/obj", method="GET")
        assert "error" in res
        assert "must be one of" in res["error"]
        assert "http_request" in res["error"]

    def test_post_is_rejected(self):
        res = execute(url="https://example.com/obj", method="POST")
        assert "error" in res
        assert "http_request" in res["error"]

    def test_missing_method_is_rejected(self):
        res = execute(url="https://example.com/obj", method="")
        assert "error" in res
        assert res["method"] == "(missing)"

    def test_lowercase_method_is_normalized_and_allowed(self):
        fake_stdout = f"\n{METRICS_DELIMITER}\n200\n0.1\nhttps://example.com/obj\n"
        fake_proc = MagicMock(returncode=0, stdout=fake_stdout, stderr="")
        with patch("shutil.which", return_value="/bin/curl"), \
             patch("subprocess.run", return_value=fake_proc), \
             patch("os.path.exists", return_value=True), \
             patch("pathlib.Path.read_text", side_effect=["HTTP/1.1 200 OK\r\n", "ok"]):
            res = execute(url="https://example.com/obj", method="put")
        assert "error" not in res
        assert res["method"] == "PUT"

    def test_write_methods_is_exactly_put_delete_patch(self):
        assert WRITE_METHODS == {"PUT", "DELETE", "PATCH"}

    def test_rejected_call_never_invokes_curl(self):
        # A rejected method must short-circuit before touching the
        # filesystem/subprocess at all -- confirms the allowlist check
        # really does gate execute_unchecked rather than running it anyway
        # and discarding the result.
        with patch("subprocess.run") as mock_run:
            execute(url="https://example.com/obj", method="GET")
            mock_run.assert_not_called()

    def test_execute_timeout(self):
        with patch("shutil.which", return_value="/bin/curl"), \
             patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=["curl"], timeout=5)):
            res = execute(url="https://example.com/obj", method="PUT", timeout=5)
            assert "error" in res
            assert "timed out after 5s" in res["error"]


class TestHttpWriteRequestParseReuse:
    """parse.py re-exports http_request's own pure functions -- no new
    parsing logic to test here, only that the re-export actually works."""

    def test_host_port_from_url(self):
        assert host_port_from_url("https://example.com/obj") == ("example.com", 443)

    def test_evidence_target_from_url(self):
        assert evidence_target_from_url("https://example.com/obj") == "example.com/obj"

    def test_parse_http_response_success(self):
        raw_result = {
            "url": "https://example.com/obj",
            "method": "PUT",
            "stdout": f"\n{METRICS_DELIMITER}\n200\n0.1\nhttps://example.com/obj\n",
            "returncode": 0,
            "raw_headers": "HTTP/1.1 200 OK\r\nETag: \"abc123\"\r\n",
            "raw_body": "",
        }
        parsed = parse_http_response(raw_result)
        assert parsed["status_code"] == 200
        assert parsed["headers"]["ETag"] == '"abc123"'
