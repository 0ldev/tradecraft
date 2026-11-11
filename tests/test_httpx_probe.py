import subprocess
from unittest.mock import patch

from tradecraft.adapters.httpx import execute as httpx_execute
from tradecraft.adapters.httpx import parse as httpx_parse
from tradecraft.tools.httpx_probe import HttpxProbe


def test_parse_probe_extracts_live_host_fields():
    stdout = (
        '{"host":"10.0.0.5","port":"443","url":"https://10.0.0.5","status_code":200,'
        '"title":"Welcome","webserver":"nginx","tech":["nginx","PHP"]}\n'
    )
    probe = httpx_parse.parse_probe(stdout)
    assert probe == {
        "host": "10.0.0.5", "port": "443", "url": "https://10.0.0.5",
        "status_code": 200, "title": "Welcome", "webserver": "nginx", "tech": ["nginx", "PHP"],
        "missing_security_headers": list(httpx_parse.SECURITY_HEADERS),
    }


def test_parse_probe_with_headers_and_security_headers_detection():
    # Real captured output format with hyphenated and underscored headers
    stdout = (
        '{"host":"webmail.examplepaint.com.br","port":"443","url":"https://webmail.examplepaint.com.br",'
        '"status_code":200,"title":"Webmail Locaweb","webserver":"nginx","tech":["jQuery"],'
        '"header":{"server":"nginx","x_frame_options":"sameorigin","content_type":"text/html"}}\n'
    )
    probe = httpx_parse.parse_probe(stdout)
    assert probe is not None
    assert "x-frame-options" not in probe["missing_security_headers"]
    assert "strict-transport-security" in probe["missing_security_headers"]
    assert "content-security-policy" in probe["missing_security_headers"]
    assert "x-content-type-options" in probe["missing_security_headers"]


def test_parse_probe_returns_none_when_host_not_live():
    assert httpx_parse.parse_probe("") is None


def test_parse_raw_extracts_full_json_dict():
    stdout = '{"host":"10.0.0.5","header":{"Server":"nginx","Set-Cookie":"id=1"}}\n'
    raw = httpx_parse.parse_raw(stdout)
    assert raw == {"host": "10.0.0.5", "header": {"Server": "nginx", "Set-Cookie": "id=1"}}


def test_parse_raw_returns_none_for_empty():
    assert httpx_parse.parse_raw("") is None


def test_execution_uses_expected_argv_and_timeout():
    process = subprocess.CompletedProcess([], 0, stdout="", stderr="")
    with patch("subprocess.run", return_value=process) as run:
        httpx_execute.execute("10.0.0.5")
    run.assert_called_once_with(
        ["pd-httpx", "-u", "10.0.0.5", "-silent", "-json", "-include-response-header", "-timeout", "10", "-retries", "1", "-follow-redirects"],
        text=True, capture_output=True, timeout=30, stdin=subprocess.DEVNULL,
    )


def test_execution_adds_header_flags_when_given():
    process = subprocess.CompletedProcess([], 0, stdout="", stderr="")
    with patch("subprocess.run", return_value=process) as run:
        httpx_execute.execute("10.0.0.5", headers="Authorization: Bearer xyz\nX-Api-Key: abc")
    argv = run.call_args[0][0]
    assert argv.count("-H") == 2
    assert "Authorization: Bearer xyz" in argv
    assert "X-Api-Key: abc" in argv


def test_execution_with_no_headers_adds_no_h_flags():
    process = subprocess.CompletedProcess([], 0, stdout="", stderr="")
    with patch("subprocess.run", return_value=process) as run:
        httpx_execute.execute("10.0.0.5")
    assert "-H" not in run.call_args[0][0]


def test_bulk_execution_also_applies_headers(tmp_path=None):
    def fake_subprocess_run(cmd, **kwargs):
        assert cmd.count("-H") == 1
        assert "Authorization: Bearer xyz" in cmd
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    with patch("subprocess.run", side_effect=fake_subprocess_run):
        httpx_execute.execute("a.com,b.com", headers="Authorization: Bearer xyz")


def test_tool_run_passes_headers_through(monkeypatch):
    captured = {}

    def fake_execute(target, headers=None):
        captured["target"] = target
        captured["headers"] = headers
        return httpx_execute.RawProbeResult(stdout="")

    monkeypatch.setattr("tradecraft.tools.httpx_probe.httpx_execute.execute", fake_execute)
    HttpxProbe().run(target="10.0.0.5", headers="Authorization: Bearer xyz")
    assert captured["headers"] == "Authorization: Bearer xyz"


def test_missing_binary_and_timeout_are_reported():
    with patch("subprocess.run", side_effect=FileNotFoundError()):
        assert httpx_execute.execute("10.0.0.5").error == "httpx executable not found"
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("httpx", 30)):
        assert httpx_execute.execute("10.0.0.5").error == "httpx timed out after 30s"


def test_run_reports_not_live_when_no_json_line():
    process = subprocess.CompletedProcess([], 1, stdout="", stderr="")
    with patch("subprocess.run", return_value=process):
        result = HttpxProbe().run(target="10.0.0.5")
    assert result == {"target": "10.0.0.5", "live": False}


def test_extract_facts_merges_status_and_title_onto_reported_host_port():
    tool = HttpxProbe()
    result = {
        "live": True, "host": "10.0.0.5", "port": 443,
        "status_code": 200, "title": "Welcome", "webserver": "nginx", "tech": [],
    }
    facts = tool.extract_facts({"target": "10.0.0.5"}, result)
    assert facts == [{"host": "10.0.0.5", "port": 443, "http_status": 200, "http_title": "Welcome"}]


def test_extract_facts_includes_missing_security_headers_when_present():
    tool = HttpxProbe()
    result = {
        "live": True, "host": "10.0.0.5", "port": 443,
        "status_code": 200, "title": "Welcome",
        "missing_security_headers": ["strict-transport-security", "content-security-policy"],
    }
    facts = tool.extract_facts({"target": "10.0.0.5"}, result)
    assert facts == [{
        "host": "10.0.0.5", "port": 443,
        "http_status": 200, "http_title": "Welcome",
        "missing_security_headers": "strict-transport-security, content-security-policy",
    }]


def test_extract_facts_includes_httpx_tech_when_present():
    tool = HttpxProbe()
    result = {
        "live": True, "host": "10.0.0.5", "port": 443,
        "status_code": 200, "title": "Welcome",
        "tech": ["Cloudflare", "WordPress"],
    }
    facts = tool.extract_facts({"target": "10.0.0.5"}, result)
    assert facts == [{
        "host": "10.0.0.5", "port": 443,
        "http_status": 200, "http_title": "Welcome",
        "httpx_tech": "Cloudflare, WordPress",
    }]


def test_extract_facts_bulk_includes_httpx_tech_when_present():
    tool = HttpxProbe()
    result = {
        "results": [
            {"host": "a.com", "port": 443, "status_code": 200, "title": "A", "tech": ["Nginx"]},
        ],
    }
    facts = tool.extract_facts({"target": "a.com"}, result)
    assert facts == [{
        "host": "a.com", "port": 443,
        "http_status": 200, "http_title": "A",
        "httpx_tech": "Nginx",
    }]


def test_extract_facts_empty_when_not_live():
    assert HttpxProbe().extract_facts({"target": "10.0.0.5"}, {"live": False}) == []


def test_extract_facts_includes_evidence_id_when_present():
    tool = HttpxProbe()
    result = {
        "live": True, "host": "10.0.0.5", "port": 443,
        "status_code": 200, "title": "Welcome",
        "evidence_id": "httpx_probe:10.0.0.5",
    }
    facts = tool.extract_facts({"target": "10.0.0.5"}, result)
    assert facts == [{
        "host": "10.0.0.5", "port": 443,
        "http_status": 200, "http_title": "Welcome",
        "evidence": "httpx_probe:10.0.0.5",
    }]


def test_extract_evidence_returns_full_dict():
    tool = HttpxProbe()
    result = {
        "target": "10.0.0.5", "live": True, "host": "10.0.0.5", "port": "443",
        "_full_evidence": {"host": "10.0.0.5", "header": {"Server": "nginx"}},
    }
    target, full, aliases = tool.extract_evidence({"target": "10.0.0.5"}, result)
    assert target == "10.0.0.5"
    assert full == {"host": "10.0.0.5", "header": {"Server": "nginx"}}
    assert aliases == []
    # Peeks, doesn't pop: tradecraft/execution/loop.py strips this key itself
    # after extract_facts has had a chance to read it too.
    assert "_full_evidence" in result


def test_normalize_targets():
    targets = "a.com, b.com ,https://c.com/path, a.com ,  "
    assert httpx_execute.normalize_targets(targets) == ["a.com", "b.com", "https://c.com/path"]
    assert httpx_execute.normalize_targets("") == []


def test_parse_probe_many():
    stdout = (
        '{"host":"a.com","port":"443","url":"https://a.com","status_code":200,"title":"A"}\n'
        'invalid json line\n'
        '{"host":"b.com","port":"80","url":"http://b.com","status_code":301,"title":"B"}\n'
    )
    results = httpx_parse.parse_probe_many(stdout)
    assert len(results) == 2
    assert results[0]["host"] == "a.com"
    assert results[0]["status_code"] == 200
    assert results[1]["host"] == "b.com"
    assert results[1]["status_code"] == 301


def test_execute_bulk_creates_temp_file_and_cleans_up():
    def fake_subprocess_run(cmd, **kwargs):
        assert "-l" in cmd
        l_idx = cmd.index("-l")
        hosts_file = cmd[l_idx + 1]
        with open(hosts_file, "r") as f:
            lines = [line.strip() for line in f if line.strip()]
        assert lines == ["a.com", "b.com"]
        assert "-rate-limit" in cmd
        assert "-threads" in cmd
        return subprocess.CompletedProcess(cmd, 0, stdout='{"host":"a.com","port":"443"}\n', stderr="")

    with patch("subprocess.run", side_effect=fake_subprocess_run):
        res = httpx_execute.execute("a.com, b.com")
        assert res.error is None
        assert "a.com" in res.stdout


def test_run_bulk_reports_counts_and_truncates_at_15():
    tool = HttpxProbe()
    fake_lines = "\n".join(
        f'{{"host":"sub{i}.example.com","port":"443","status_code":200,"title":"Site {i}"}}'
        for i in range(20)
    ) + "\n"

    with patch("tradecraft.tools.httpx_probe.httpx_execute.execute") as mock_exec:
        mock_exec.return_value = httpx_execute.RawProbeResult(stdout=fake_lines)
        res = tool.run("sub0.example.com,sub1.example.com")
        assert res["probed_count"] == 2
        assert res["live_count"] == 20
        assert len(res["results"]) == 15
        assert res["omitted_results"] == 5
        assert "more probed hosts omitted" in res["note"]

        # Fact extraction in bulk must cover every live host, not just the
        # 15 kept in res["results"] for display -- a host beyond the
        # truncation cutoff still needs a fact row (with its own
        # read_evidence pointer) or it's silently invisible in Known Facts
        # even though its data is sitting in the evidence store. This
        # relies on `_full_evidence` still being present on `res` (not yet
        # stripped by tradecraft/execution/loop.py, which does so only after
        # calling extract_facts in the real loop).
        facts = tool.extract_facts({"target": "sub0.example.com,sub1.example.com"}, res)
        assert len(facts) == 20
        assert facts[0]["host"] == "sub0.example.com"
        assert facts[0]["port"] == 443
        assert facts[0]["http_status"] == 200
        assert facts[0]["http_title"] == "Site 0"
        assert "content-security-policy" in facts[0]["missing_security_headers"]
        # A host past the display cutoff (index 15) still gets a fact.
        assert facts[19]["host"] == "sub19.example.com"
        assert facts[19]["http_status"] == 200

        # Evidence extraction in bulk keys off first host
        canonical, full, aliases = tool.extract_evidence({"target": "sub0.example.com,sub1.example.com"}, res)
        assert canonical == "sub0.example.com"
        assert len(full["results"]) == 20
        assert aliases == ["sub1.example.com"]
        # extract_evidence peeks rather than pops -- extract_facts (called
        # after it in the real loop) still needs _full_evidence present.
        assert "_full_evidence" in res


def test_extract_facts_falls_back_to_truncated_results_without_full_evidence():
    # If _full_evidence was already stripped (e.g. a caller that only has
    # the model-facing result, not the live in-loop dict), fall back to
    # whatever's in result["results"] rather than erroring.
    tool = HttpxProbe()
    result = {
        "results": [{"host": "a.com", "port": 443, "status_code": 200, "title": "A"}],
        "omitted_results": 5,
    }
    facts = tool.extract_facts({"target": "a.com"}, result)
    assert facts == [{"host": "a.com", "port": 443, "http_status": 200, "http_title": "A"}]

