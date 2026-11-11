"""Unit tests for gau adapter (execute and parse)."""
import subprocess
from unittest.mock import MagicMock, patch

import requests

from tradecraft.adapters.gau.execute import (
    RawGauResult,
    build_argv,
    execute,
    normalize_target_domain,
)
from tradecraft.adapters.gau.parse import host_port_from_target, parse_gau_output

MOCK_GAU_STDOUT = """
time="2026-11-01T15:45:32Z" level=warning msg="error reading config: Config file /root/.gau.toml not found, using default config"
http://examplepaint.com.br:80/
https://examplepaint.com.br/.well-known/security.txt
https://examplepaint.com.br/admin/login?redirect=/dashboard&v=1
https://sub.examplepaint.com.br/api/search?q=
https://examplepaint.com.br/frontend/dist/images/logo.png
https://examplepaint.com.br/frontend/dist/css/padrao.css
https://otherdomain.com/unrelated
"""


class TestGauExecute:
    def test_normalize_target_domain(self):
        assert normalize_target_domain("example.com") == "example.com"
        assert normalize_target_domain("https://example.com/test") == "example.com"
        assert normalize_target_domain("http://example.com:8080/path") == "example.com"
        assert normalize_target_domain("sub.example.com:443") == "sub.example.com"
        assert normalize_target_domain("") == ""

    def test_build_argv_default(self):
        argv = build_argv("example.com")
        assert argv == [
            "gau",
            "example.com",
            "--providers", "wayback,otx",
            "--timeout", "25",
            "--subs",
        ]

    def test_build_argv_custom(self):
        argv = build_argv(
            "example.com",
            include_subs=False,
            providers="wayback,commoncrawl",
            timeout=20,
        )
        assert "--subs" not in argv
        assert argv[argv.index("--providers") + 1] == "wayback,commoncrawl"
        assert argv[argv.index("--timeout") + 1] == "20"

    def test_execute_empty_target(self):
        res = execute("")
        assert res.error == "empty target"

    @patch("tradecraft.adapters.gau.execute.requests.get")
    @patch("tradecraft.adapters.gau.execute.shutil.which", return_value=None)
    def test_execute_missing_binary_falls_back(self, mock_which, mock_get):
        mock_get.side_effect = requests.exceptions.ConnectionError("offline")
        res = execute("example.com")
        assert "gau binary not found" in (res.error or "")

    @patch("tradecraft.adapters.gau.execute.subprocess.run")
    def test_execute_success(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = MOCK_GAU_STDOUT
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        res = execute("https://examplepaint.com.br")
        assert res.error is None
        assert res.returncode == 0
        assert "security.txt" in res.stdout

    @patch("tradecraft.adapters.gau.execute.requests.get")
    @patch("tradecraft.adapters.gau.execute.subprocess.run")
    def test_execute_timeout(self, mock_run, mock_get):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["gau"], timeout=60)
        mock_get.side_effect = requests.exceptions.ConnectionError("offline")
        res = execute("https://example.com")
        assert "gau timed out" in (res.error or "")


class TestGauParse:
    def test_host_port_from_target(self):
        assert host_port_from_target("example.com") == ("example.com", 80)
        assert host_port_from_target("https://example.com") == ("example.com", 443)
        assert host_port_from_target("http://example.com:8080") == ("example.com", 8080)

    def test_parse_real_captured_output(self):
        parsed = parse_gau_output(MOCK_GAU_STDOUT, base_domain="examplepaint.com.br")
        assert parsed["total_urls"] == 7

        # Subdomains check: should filter to examplepaint.com.br subdomains
        assert "sub.examplepaint.com.br" in parsed["subdomains"]
        assert "examplepaint.com.br" in parsed["subdomains"]
        assert "otherdomain.com" not in parsed["subdomains"]

        # Endpoints check: should filter out .png and .css
        assert "/.well-known/security.txt" in parsed["endpoints"]
        assert "/admin/login" in parsed["endpoints"]
        assert "/api/search" in parsed["endpoints"]
        assert not any(ep.endswith(".png") for ep in parsed["endpoints"])
        assert not any(ep.endswith(".css") for ep in parsed["endpoints"])

        # Parameters check: should include query params with and without values
        assert "q" in parsed["parameters"]
        assert "redirect" in parsed["parameters"]
        assert "v" in parsed["parameters"]

    def test_parse_empty_and_noise_output(self):
        assert parse_gau_output("") == {
            "urls": [],
            "endpoints": [],
            "subdomains": [],
            "parameters": [],
            "total_urls": 0,
            "total_endpoints": 0,
            "total_subdomains": 0,
            "total_parameters": 0,
        }
        noise = 'time="2026-11-01T15:45:32Z" level=warning msg="config error"\n\n'
        assert parse_gau_output(noise) == {
            "urls": [],
            "endpoints": [],
            "subdomains": [],
            "parameters": [],
            "total_urls": 0,
            "total_endpoints": 0,
            "total_subdomains": 0,
            "total_parameters": 0,
        }


WAYBACK_TEXT = "https://examplepaint.com.br/admin/login\nhttps://examplepaint.com.br/shared\n"
OTX_JSON = {
    "url_list": [
        {"url": "https://examplepaint.com.br/shared", "date": "2026-01-01"},
        {"url": "https://sub.examplepaint.com.br/api/v1/items?id=3", "date": "2026-01-02"},
    ],
    "has_next": False,
    "paged": False,
}


def _resp(status=200, text="", payload=None):
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.json.return_value = payload if payload is not None else {}
    return r


def _route(wayback, otx):
    """Build a requests.get side_effect dispatching on URL.

    `wayback` / `otx` are either a response object or an Exception to raise.
    """
    def fake_get(url, timeout=None):
        assert timeout == 10
        handler = wayback if "web.archive.org" in url else otx
        if isinstance(handler, Exception):
            raise handler
        return handler
    return fake_get


class TestGauPythonFallback:
    @patch("tradecraft.adapters.gau.execute.requests.get")
    @patch("tradecraft.adapters.gau.execute.subprocess.run")
    @patch("tradecraft.adapters.gau.execute.shutil.which", return_value="/usr/bin/gau")
    def test_gau_success_no_fallback(self, _which, mock_run, mock_get):
        mock_run.return_value = MagicMock(stdout=MOCK_GAU_STDOUT, stderr="", returncode=0)
        res = execute("examplepaint.com.br")
        assert res.error is None
        assert res.stdout == MOCK_GAU_STDOUT
        mock_get.assert_not_called()

    @patch("tradecraft.adapters.gau.execute.requests.get")
    @patch("tradecraft.adapters.gau.execute.subprocess.run")
    @patch("tradecraft.adapters.gau.execute.shutil.which", return_value="/usr/bin/gau")
    def test_gau_timeout_triggers_both_sources_and_merges(self, _which, mock_run, mock_get):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["gau"], timeout=30)
        mock_get.side_effect = _route(
            _resp(text=WAYBACK_TEXT),
            _resp(payload=OTX_JSON),
        )
        res = execute("examplepaint.com.br")
        assert res.error is None
        assert mock_get.call_count == 2
        urls = res.stdout.splitlines()
        # Union + dedupe: /shared appears in both sources but only once.
        assert urls == sorted({
            "https://examplepaint.com.br/admin/login",
            "https://examplepaint.com.br/shared",
            "https://sub.examplepaint.com.br/api/v1/items?id=3",
        })
        # Output feeds parse_gau_output unchanged.
        parsed = parse_gau_output(res.stdout, base_domain="examplepaint.com.br")
        assert parsed["total_urls"] == 3
        assert "/api/v1/items" in parsed["endpoints"]

    @patch("tradecraft.adapters.gau.execute.requests.get")
    @patch("tradecraft.adapters.gau.execute.subprocess.run")
    @patch("tradecraft.adapters.gau.execute.shutil.which", return_value="/usr/bin/gau")
    def test_gau_zero_urls_triggers_fallback(self, _which, mock_run, mock_get):
        mock_run.return_value = MagicMock(
            stdout='time="2026-11-01T15:45:32Z" level=warning msg="noise"\n',
            stderr="",
            returncode=0,
        )
        mock_get.side_effect = _route(_resp(text=WAYBACK_TEXT), _resp(payload=OTX_JSON))
        res = execute("examplepaint.com.br")
        assert res.error is None
        assert mock_get.call_count == 2
        assert len(res.stdout.splitlines()) == 3

    @patch("tradecraft.adapters.gau.execute.requests.get")
    @patch("tradecraft.adapters.gau.execute.subprocess.run")
    @patch("tradecraft.adapters.gau.execute.shutil.which", return_value="/usr/bin/gau")
    def test_one_source_exception_other_still_used(self, _which, mock_run, mock_get):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["gau"], timeout=30)
        mock_get.side_effect = _route(
            requests.exceptions.ConnectionError("cdx down"),
            _resp(payload=OTX_JSON),
        )
        res = execute("examplepaint.com.br")
        assert res.error is None
        assert mock_get.call_count == 2
        assert len(res.stdout.splitlines()) == 2

    @patch("tradecraft.adapters.gau.execute.requests.get")
    @patch("tradecraft.adapters.gau.execute.subprocess.run")
    @patch("tradecraft.adapters.gau.execute.shutil.which", return_value="/usr/bin/gau")
    def test_one_source_non_200_other_still_used(self, _which, mock_run, mock_get):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["gau"], timeout=30)
        mock_get.side_effect = _route(_resp(status=503), _resp(payload=OTX_JSON))
        res = execute("examplepaint.com.br")
        assert res.error is None
        assert len(res.stdout.splitlines()) == 2

    @patch("tradecraft.adapters.gau.execute.requests.get")
    @patch("tradecraft.adapters.gau.execute.subprocess.run")
    @patch("tradecraft.adapters.gau.execute.shutil.which", return_value="/usr/bin/gau")
    def test_both_sources_fail_returns_original_error(self, _which, mock_run, mock_get):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["gau"], timeout=30)
        mock_get.side_effect = _route(
            requests.exceptions.Timeout("cdx slow"),
            _resp(status=500),
        )
        res = execute("examplepaint.com.br")
        assert res.stdout == ""
        assert res.error == "gau timed out after 30s"
        assert mock_get.call_count == 2

    @patch("tradecraft.adapters.gau.execute.requests.get")
    @patch("tradecraft.adapters.gau.execute.subprocess.run")
    @patch("tradecraft.adapters.gau.execute.shutil.which", return_value="/usr/bin/gau")
    def test_fallback_wayback_json_error_is_zero_urls(self, _which, mock_run, mock_get):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["gau"], timeout=30)
        bad_json = _resp(status=200)
        bad_json.json.side_effect = ValueError("not json")
        mock_get.side_effect = _route(_resp(text=WAYBACK_TEXT), bad_json)
        res = execute("examplepaint.com.br")
        assert res.error is None
        assert len(res.stdout.splitlines()) == 2

    @patch("tradecraft.adapters.gau.execute.requests.get")
    @patch("tradecraft.adapters.gau.execute.shutil.which", return_value=None)
    def test_missing_binary_still_uses_fallback(self, _which, mock_get):
        mock_get.side_effect = _route(_resp(text=WAYBACK_TEXT), _resp(payload=OTX_JSON))
        res = execute("examplepaint.com.br")
        assert res.error is None
        assert mock_get.call_count == 2
        assert len(res.stdout.splitlines()) == 3

    @patch("tradecraft.adapters.gau.execute.requests.get")
    @patch("tradecraft.adapters.gau.execute.subprocess.run")
    @patch("tradecraft.adapters.gau.execute.shutil.which", return_value="/usr/bin/gau")
    def test_fallback_respects_providers_otx_only(self, _which, mock_run, mock_get):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["gau"], timeout=30)
        mock_get.side_effect = _route(_resp(text=WAYBACK_TEXT), _resp(payload=OTX_JSON))
        res = execute("examplepaint.com.br", providers="otx")
        assert res.error is None
        assert mock_get.call_count == 1
        called_url = mock_get.call_args_list[0].args[0]
        assert "otx" in called_url or "alienvault" in called_url
        assert len(res.stdout.splitlines()) == 2

    @patch("tradecraft.adapters.gau.execute.requests.get")
    @patch("tradecraft.adapters.gau.execute.subprocess.run")
    @patch("tradecraft.adapters.gau.execute.shutil.which", return_value="/usr/bin/gau")
    def test_fallback_respects_providers_wayback_only(self, _which, mock_run, mock_get):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["gau"], timeout=30)
        mock_get.side_effect = _route(_resp(text=WAYBACK_TEXT), _resp(payload=OTX_JSON))
        res = execute("examplepaint.com.br", providers="wayback")
        assert res.error is None
        assert mock_get.call_count == 1
        called_url = mock_get.call_args_list[0].args[0]
        assert "web.archive.org" in called_url
        assert len(res.stdout.splitlines()) == 2
