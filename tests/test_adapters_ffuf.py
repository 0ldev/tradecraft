"""Unit tests for wordlists resolver and ffuf adapter (execute and parse)."""
import json
import os
from unittest.mock import MagicMock, patch

import pytest

from tradecraft.adapters.ffuf.execute import (
    DEFAULT_THREADS,
    MAX_THREADS,
    CanarySignature,
    RawFfufResult,
    build_argv,
    count_wordlist_requests,
    execute,
    normalize_extensions,
    normalize_target_url,
    probe_canary,
)
from tradecraft.adapters.ffuf.parse import host_port_from_target, parse_results
from tradecraft.adapters.wordlists import WORDLISTS_DIR, resolve_wordlist


class TestWordlistResolution:
    def test_bare_name_resolves_to_bundled(self):
        res = resolve_wordlist("common")
        assert res == str(WORDLISTS_DIR / "common.txt")
        assert os.path.exists(res)

    def test_small_wordlist_resolves_to_bundled(self):
        res = resolve_wordlist("small")
        assert res == str(WORDLISTS_DIR / "small.txt")
        assert os.path.exists(res)

    def test_bare_name_with_txt_resolves_to_bundled(self):
        res = resolve_wordlist("admin.txt")
        assert res == str(WORDLISTS_DIR / "admin.txt")
        assert os.path.exists(res)

    def test_external_path_with_matching_basename_resolves_to_bundled(self):
        res = resolve_wordlist("/opt/SecLists/Discovery/Web-Content/common.txt")
        assert res == str(WORDLISTS_DIR / "common.txt")

    def test_exact_existing_file_resolves(self, tmp_path):
        custom_file = tmp_path / "custom.txt"
        custom_file.write_text("endpoint1\nendpoint2")
        res = resolve_wordlist(str(custom_file))
        assert res == str(custom_file)

    def test_nonexistent_name_falls_back_to_common(self):
        res = resolve_wordlist("totally_nonexistent_wordlist_xyz")
        assert res == str(WORDLISTS_DIR / "common.txt")

    def test_cwd_independence(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        res = resolve_wordlist("common")
        assert res == str(WORDLISTS_DIR / "common.txt")
        assert os.path.exists(res)


class TestFfufExecute:
    def test_normalize_target_url(self):
        assert normalize_target_url("https://example.com") == "https://example.com/FUZZ"
        assert normalize_target_url("https://example.com/") == "https://example.com/FUZZ"
        assert normalize_target_url("http://example.com/api") == "http://example.com/api/FUZZ"
        assert normalize_target_url("example.com") == "https://example.com/FUZZ"
        assert normalize_target_url("example.com:80") == "http://example.com:80/FUZZ"
        assert normalize_target_url("example.com:8443") == "https://example.com:8443/FUZZ"
        assert normalize_target_url("https://example.com/api/FUZZ") == "https://example.com/api/FUZZ"

    def test_normalize_extensions(self):
        assert normalize_extensions("") == ""
        assert normalize_extensions("php,html") == ".php,.html"
        assert normalize_extensions(".php,.html") == ".php,.html"
        assert normalize_extensions(["php", "html", "txt"]) == ".php,.html,.txt"
        assert normalize_extensions([" .php ", "html "]) == ".php,.html"

    def test_build_argv(self):
        cmd = build_argv(
            target_url="https://example.com/FUZZ",
            wordlist_path="/path/to/wordlist.txt",
            out_file="/tmp/out.json",
            extensions="php,html",
            match_codes="200,301",
            filter_codes="404",
        )
        assert cmd == [
            "ffuf",
            "-u", "https://example.com/FUZZ",
            "-w", "/path/to/wordlist.txt",
            "-mc", "200,301",
            "-fc", "404",
            "-of", "json",
            "-o", "/tmp/out.json",
            "-t", str(DEFAULT_THREADS),
            "-s",
            "-e", ".php,.html",
        ]

    def test_build_argv_caps_threads_regardless_of_input(self):
        # Requesting far more than MAX_THREADS still clamps to the hard cap --
        # this is an adapter-level containment, not a model-tunable knob.
        cmd = build_argv(
            target_url="https://example.com/FUZZ",
            wordlist_path="/path/to/wordlist.txt",
            out_file="/tmp/out.json",
            threads=9999,
        )
        assert "-t" in cmd and cmd[cmd.index("-t") + 1] == str(MAX_THREADS)

    def test_build_argv_threads_floor(self):
        cmd = build_argv(
            target_url="https://example.com/FUZZ",
            wordlist_path="/path/to/wordlist.txt",
            out_file="/tmp/out.json",
            threads=0,
        )
        assert "-t" in cmd and cmd[cmd.index("-t") + 1] == "1"

    def test_count_wordlist_requests(self, tmp_path):
        wl = tmp_path / "words.txt"
        wl.write_text("admin\nlogin\n\n# comment-looking but still counted as a word\nbackup\n")
        # 4 non-blank lines, no extensions -> 4 requests
        assert count_wordlist_requests(str(wl)) == 4
        # 4 words * (1 base + 2 extensions) = 12
        assert count_wordlist_requests(str(wl), extensions="php,bak") == 12

    def test_count_wordlist_requests_missing_file(self):
        assert count_wordlist_requests("/no/such/wordlist.txt") == 0

    @patch("tradecraft.adapters.ffuf.execute.requests.get")
    def test_probe_canary_success(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 302
        mock_resp.content = b""
        mock_resp.headers = {"Location": "//example.com/conteudo"}
        mock_get.return_value = mock_resp

        canary = probe_canary("https://example.com")
        assert canary is not None
        assert canary.status_code == 302
        assert canary.length == 0
        assert canary.redirect_location == "//example.com/conteudo"

    @patch("tradecraft.adapters.ffuf.execute.requests.get", side_effect=Exception("network down"))
    def test_probe_canary_failure_degrades_gracefully(self, mock_get):
        canary = probe_canary("https://example.com")
        assert canary is None

    @patch("tradecraft.adapters.ffuf.execute.probe_canary", return_value=CanarySignature(302, 0, "//catchall"))
    @patch("tradecraft.adapters.ffuf.execute.subprocess.run")
    def test_execute_success(self, mock_subproc, mock_canary, tmp_path):
        sample_json = json.dumps({
            "results": [
                {
                    "input": {"FUZZ": "admin"},
                    "status": 200,
                    "length": 1500,
                    "words": 200,
                    "lines": 30,
                    "url": "https://example.com/admin",
                }
            ]
        })

        def fake_run(cmd, **kwargs):
            out_idx = cmd.index("-o") + 1
            out_path = cmd[out_idx]
            with open(out_path, "w") as f:
                f.write(sample_json)
            return MagicMock(stdout="", stderr="", returncode=0)

        mock_subproc.side_effect = fake_run

        raw = execute(target="https://example.com", wordlist="common")
        assert raw.error is None
        assert raw.canary == CanarySignature(302, 0, "//catchall")
        assert "admin" in raw.json_output
        # Real bundled wordlist -> a real non-zero request-volume estimate.
        assert raw.requests_attempted > 0
        assert raw.duration_seconds >= 0
        # The subprocess call itself was capped to the hardcoded thread limit.
        called_argv = mock_subproc.call_args[0][0]
        assert "-t" in called_argv and int(called_argv[called_argv.index("-t") + 1]) <= MAX_THREADS


class TestFfufParse:
    def test_host_port_from_target(self):
        assert host_port_from_target("https://example.com") == ("example.com", 443)
        assert host_port_from_target("http://example.com") == ("example.com", 80)
        assert host_port_from_target("example.com") == ("example.com", 443)
        assert host_port_from_target("example.com:8080") == ("example.com", 8080)
        assert host_port_from_target("https://example.com:8443/FUZZ") == ("example.com", 8443)

    def test_parse_clean_results(self):
        raw = json.dumps({
            "results": [
                {
                    "input": {"FUZZ": "admin"},
                    "status": 200,
                    "length": 1500,
                    "words": 200,
                    "lines": 30,
                    "url": "https://example.com/admin",
                },
                {
                    "input": {"FUZZ": "api/v1"},
                    "status": 200,
                    "length": 250,
                    "words": 10,
                    "lines": 2,
                    "url": "https://example.com/api/v1",
                },
            ]
        })
        endpoints = parse_results(raw)
        assert len(endpoints) == 2
        assert endpoints[0]["path"] == "/admin"
        assert endpoints[0]["status_code"] == 200
        assert endpoints[0]["length"] == 1500
        assert endpoints[1]["path"] == "/api/v1"

    def test_canary_filtering_exact_length(self):
        raw = json.dumps({
            "results": [
                {
                    "input": {"FUZZ": "robots.txt"},
                    "status": 302,
                    "length": 0,
                    "redirectlocation": "//example.com/conteudo",
                    "url": "https://example.com/robots.txt",
                },
                {
                    "input": {"FUZZ": "admin"},
                    "status": 200,
                    "length": 11170,
                    "url": "https://example.com/admin",
                },
            ]
        })
        canary = CanarySignature(status_code=302, length=0, redirect_location="//example.com/conteudo")
        endpoints = parse_results(raw, canary=canary)
        assert len(endpoints) == 1
        assert endpoints[0]["path"] == "/admin"
        assert endpoints[0]["status_code"] == 200

    def test_canary_filtering_catchall_redirect(self):
        raw = json.dumps({
            "results": [
                {
                    "input": {"FUZZ": "bogus-path"},
                    "status": 301,
                    "length": 15,
                    "redirectlocation": "//example.com/home",
                    "url": "https://example.com/bogus-path",
                },
                {
                    "input": {"FUZZ": "login"},
                    "status": 200,
                    "length": 800,
                    "url": "https://example.com/login",
                },
            ]
        })
        canary = CanarySignature(status_code=301, length=123, redirect_location="//example.com/home")
        endpoints = parse_results(raw, canary=canary)
        assert len(endpoints) == 1
        assert endpoints[0]["path"] == "/login"

    def test_dominant_shell_filtering(self):
        # 10 endpoints with identical length 100, 1 genuine endpoint with length 512
        results = [
            {
                "input": {"FUZZ": f"phantom{i}"},
                "status": 200,
                "length": 100,
                "url": f"https://example.com/phantom{i}",
            }
            for i in range(10)
        ]
        results.append({
            "input": {"FUZZ": "real"},
            "status": 200,
            "length": 512,
            "url": "https://example.com/real",
        })
        raw = json.dumps({"results": results})
        endpoints = parse_results(raw)
        assert len(endpoints) == 1
        assert endpoints[0]["path"] == "/real"
        assert endpoints[0]["length"] == 512

    def test_empty_and_malformed_json(self):
        assert parse_results("") == []
        assert parse_results("{bad-json") == []
        assert parse_results("{}") == []
