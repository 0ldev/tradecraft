"""Unit tests for katana adapter (execute and parse)."""
import subprocess
from unittest.mock import MagicMock, patch

from tradecraft.adapters.katana.execute import (
    RawKatanaResult,
    build_argv,
    execute,
    normalize_target_url,
)
from tradecraft.adapters.katana.parse import host_port_from_target, parse_katana_output

MOCK_KATANA_JSONL = """
{"timestamp":"2026-11-01T13:15:45.265138635Z","request":{"method":"GET","endpoint":"https://examplepaint.com.br"},"response":{"status_code":200,"headers":{"Server":"Apache"},"content_length":105339}}
{"timestamp":"2026-11-01T13:15:46.06119468Z","request":{"method":"GET","endpoint":"https://examplepaint.com.br/frontend/dist/js/main.min.js","tag":"script","attribute":"src","source":"https://examplepaint.com.br"},"response":{"status_code":200,"headers":{"Server":"Apache"},"content_length":1525}}
{"timestamp":"2026-11-01T13:15:46.100140445Z","request":{"method":"GET","endpoint":"https://examplepaint.com.br/frontend/dist/css/padrao.css?v=1","tag":"link","attribute":"href","source":"https://examplepaint.com.br"},"response":{"status_code":200,"headers":{"Server":"Apache"},"content_length":14729}}
{"timestamp":"2026-11-01T13:15:46.171664105Z","request":{"method":"GET","endpoint":"https://examplepaint.com.br/admin","tag":"a","attribute":"href","source":"https://examplepaint.com.br"},"response":{"status_code":200,"headers":{"Server":"Apache"},"content_length":11187}}
{"timestamp":"2026-11-01T13:15:46.175284735Z","request":{"method":"GET","endpoint":"https://examplepaint.com.br/frontend/dist/css/admin.css?v=5&theme=dark","tag":"link","attribute":"href","source":"https://examplepaint.com.br/admin"},"error":"max depth reached"}
{"timestamp":"2026-11-01T13:15:46.175584176Z","request":{"method":"GET","endpoint":"https://examplepaint.com.br/search?q=","tag":"form","attribute":"action","source":"https://examplepaint.com.br"},"error":"max depth reached"}
{"corrupted json line
"""


class TestKatanaExecute:
    def test_normalize_target_url(self):
        assert normalize_target_url("example.com") == "https://example.com"
        assert normalize_target_url("http://example.com") == "http://example.com"
        assert normalize_target_url("https://example.com/test") == "https://example.com/test"
        assert normalize_target_url("example.com:80") == "http://example.com:80"
        assert normalize_target_url("example.com:443") == "https://example.com:443"
        assert normalize_target_url("") == ""

    def test_build_argv_default(self):
        argv = build_argv("https://example.com")
        assert argv == [
            "katana",
            "-u", "https://example.com",
            "-d", "2",
            "-fs", "rdn",
            "-fsu",
            "-ob",
            "-or",
            "-silent",
            "-j",
            "-c", "10",
            "-rl", "150",
            "-ct", "15s",
            "-jc",
        ]

    def test_build_argv_no_js_crawl(self):
        argv = build_argv("https://example.com", js_crawl=False, depth=1, crawl_duration=5)
        assert "-jc" not in argv
        assert "-d" in argv and argv[argv.index("-d") + 1] == "1"
        assert "-ct" in argv and argv[argv.index("-ct") + 1] == "5s"

    def test_build_argv_headless(self):
        argv = build_argv("https://example.com", headless=True)
        assert "-hl" in argv
        assert "-nos" in argv
        assert "-sc" in argv

    def test_build_argv_headless_no_system_chrome(self):
        argv = build_argv("https://example.com", headless=True, system_chrome=False)
        assert "-hl" in argv
        assert "-nos" in argv
        assert "-sc" not in argv

    def test_execute_empty_target(self):
        res = execute("")
        assert res.error == "empty target"

    @patch("tradecraft.adapters.katana.execute.shutil.which", return_value=None)
    def test_execute_missing_binary(self, mock_which):
        res = execute("example.com")
        assert "katana binary not found" in (res.error or "")

    @patch("tradecraft.adapters.katana.execute.subprocess.run")
    def test_execute_success(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.stdout = MOCK_KATANA_JSONL
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc

        res = execute("https://examplepaint.com.br")
        assert res.error is None
        assert res.returncode == 0
        assert "examplepaint.com.br" in res.stdout

    @patch("tradecraft.adapters.katana.execute.subprocess.run")
    def test_execute_timeout(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["katana"], timeout=45)
        res = execute("https://example.com")
        assert "katana timed out" in (res.error or "")


class TestKatanaParse:
    def test_host_port_from_target(self):
        assert host_port_from_target("example.com") == ("example.com", 80)
        assert host_port_from_target("https://example.com") == ("example.com", 443)
        assert host_port_from_target("http://example.com:8080") == ("example.com", 8080)
        assert host_port_from_target("https://example.com:8443") == ("example.com", 8443)

    def test_parse_real_captured_output(self):
        parsed = parse_katana_output(MOCK_KATANA_JSONL)
        assert parsed["total_endpoints"] == 6
        endpoints = parsed["endpoints"]

        apex = next(e for e in endpoints if e["path"] == "/")
        assert apex["endpoint"] == "https://examplepaint.com.br"
        assert apex["status_code"] == 200

        js_ep = next(e for e in endpoints if "main.min.js" in e["path"])
        assert js_ep["tag"] == "script"

        css_ep = next(e for e in endpoints if "admin.css" in e["path"])
        assert sorted(css_ep["parameters"]) == ["theme", "v"]

        search_ep = next(e for e in endpoints if "/search" in e["path"])
        assert search_ep["parameters"] == ["q"]

        assert sorted(parsed["parameters"]) == ["q", "theme", "v"]

    def test_parse_empty_and_noise_output(self):
        assert parse_katana_output("") == {
            "endpoints": [],
            "parameters": [],
            "total_endpoints": 0,
            "total_parameters": 0,
        }
        noise = "some random banner text\n\n{invalid json}\n"
        assert parse_katana_output(noise) == {
            "endpoints": [],
            "parameters": [],
            "total_endpoints": 0,
            "total_parameters": 0,
        }
