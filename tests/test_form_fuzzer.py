"""
Unit tests for form_fuzzer adapter and tool layer.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests

from tradecraft.adapters.form_fuzzer import execute as form_execute
from tradecraft.adapters.form_fuzzer import parse as form_parse
from tradecraft.tools.form_fuzzer import FormFuzzer


def test_normalize_target_url():
    assert form_parse.normalize_target_url("example.com") == "http://example.com"
    assert form_parse.normalize_target_url("https://example.com/fetch") == "https://example.com/fetch"
    assert form_parse.normalize_target_url("   ") == ""


def test_parse_host_port():
    assert form_parse.parse_host_port("http://example.com") == ("example.com", 80)
    assert form_parse.parse_host_port("https://example.com/fetch") == ("example.com", 443)
    assert form_parse.parse_host_port("http://example.com:8080/form") == ("example.com", 8080)


def test_extract_forms():
    html = """
    <html>
      <body>
        <form action="/api/fetch" method="POST">
          <input type="text" name="url" value="https://example.com">
          <input type="hidden" name="csrf" value="secret123">
          <textarea name="notes">Default note</textarea>
          <input type="submit" value="Submit">
        </form>
        <form action="search.php" method="GET">
          <input type="text" name="q" value="">
          <button type="submit">Search</button>
        </form>
      </body>
    </html>
    """
    forms = form_parse.extract_forms(html, "https://target.com/page/")
    assert len(forms) == 2

    # Form 1
    assert forms[0].action_url == "https://target.com/api/fetch"
    assert forms[0].method == "post"
    assert "url" in forms[0].fields_to_test
    assert "notes" in forms[0].fields_to_test
    assert "csrf" not in forms[0].fields_to_test  # hidden field not in fields_to_test
    assert forms[0].base_data["csrf"] == "secret123"

    # Form 2
    assert forms[1].action_url == "https://target.com/page/search.php"
    assert forms[1].method == "get"
    assert forms[1].fields_to_test == ["q"]


def test_create_synthetic_form():
    # URL with query params
    form = form_parse.create_synthetic_form("https://target.com/proxy?endpoint=test&timeout=5")
    assert form is not None
    assert form.action_url == "https://target.com/proxy"
    assert "endpoint" in form.fields_to_test
    assert "timeout" in form.fields_to_test

    # URL without params but with target_param
    form2 = form_parse.create_synthetic_form("https://target.com/fetch", target_param="url")
    assert form2 is not None
    assert form2.fields_to_test == ["url"]

    # Clean URL with no params and no target_param
    assert form_parse.create_synthetic_form("https://target.com/fetch") is None


def test_build_payloads():
    payloads_default = form_parse.build_payloads()
    assert payloads_default["ssrf"] == "http://169.254.169.254/latest/meta-data/"
    assert "ssti_true" in payloads_default
    assert "sqli" in payloads_default

    payloads_custom = form_parse.build_payloads(internal_url="http://169.254.169.254/metadata/instance")
    assert payloads_custom["ssrf"] == "http://169.254.169.254/metadata/instance"


def test_check_ssrf_response():
    body_hit = '{"ami-id": "ami-12345678", "instance-id": "i-abcdef0123456789"}'
    vuln, vtype, snippet = form_parse.check_ssrf_response(200, body_hit)
    assert vuln is True
    assert vtype == "ssrf_cloud_metadata"
    assert "ami-id" in snippet

    # 404 with text should not count
    vuln_404, _, _ = form_parse.check_ssrf_response(404, body_hit)
    assert vuln_404 is False

    # 200 without indicators
    vuln_clean, _, _ = form_parse.check_ssrf_response(200, "<html><body>Hello</body></html>")
    assert vuln_clean is False


def test_check_sqli_response():
    body_err = "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"
    vuln, vtype, snippet = form_parse.check_sqli_response(body_err)
    assert vuln is True
    assert vtype == "sqli_error"
    assert "SQL syntax" in snippet

    vuln_clean, _, _ = form_parse.check_sqli_response("Normal content")
    assert vuln_clean is False


def test_check_ssti_differential():
    true_body = "Hello User! Total points: 49 and rank: first"
    false_body = "Hello User! Total points: 42 and rank: first"
    vuln, vtype, snippet = form_parse.check_ssti_differential(true_body, false_body)
    assert vuln is True
    assert vtype == "ssti_differential"

    # Both contain 49 -> not differential
    vuln_both, _, _ = form_parse.check_ssti_differential("49", "49")
    assert vuln_both is False


def test_check_xss_response():
    payload = "<script>alert(1)</script>"
    vuln, vtype, snippet = form_parse.check_xss_response(f"<div>Result: {payload}</div>", payload)
    assert vuln is True
    assert vtype == "xss_reflection"


def test_execute_with_mock_session():
    mock_session = MagicMock()

    initial_resp = MagicMock()
    initial_resp.status_code = 200
    initial_resp.text = '<form action="/fetch" method="GET"><input type="text" name="url" value=""></form>'

    # Fuzz responses: SSTI true, SSTI false, SSRF, SQLi, XSS
    ssti_t = MagicMock(status_code=200, text="Not evaluated")
    ssti_f = MagicMock(status_code=200, text="Not evaluated")
    ssrf_r = MagicMock(status_code=200, text='{"instance-id": "i-0987654321", "local-hostname": "ip-10-0-1-5"}')
    sqli_r = MagicMock(status_code=200, text="Clean page")
    xss_r = MagicMock(status_code=200, text="Clean page")

    mock_session.get.side_effect = [initial_resp, ssti_t, ssti_f, ssrf_r, sqli_r, xss_r]

    raw = form_execute.execute("http://example.com", session=mock_session)
    assert raw.forms_found == 1
    assert raw.fields_tested == 1
    assert len(raw.vulnerabilities) == 1
    assert raw.vulnerabilities[0].vulnerability_type == "ssrf"
    assert raw.vulnerabilities[0].parameter == "url"

    parsed = form_parse.parse_form_fuzzer_result(raw)
    assert parsed["vulnerable"] is True
    assert parsed["forms_found"] == 1


def test_execute_empty_target():
    res = form_execute.execute("")
    assert res.error == "empty target URL"


def test_tool_run_and_facts_evidence():
    tool = FormFuzzer()
    assert tool.tool_id == "form_fuzzer"

    with patch("tradecraft.adapters.form_fuzzer.execute.execute") as mock_exec:
        mock_raw = form_parse.RawFormFuzzerResult(
            target="https://target.com/search",
            forms_found=1,
            fields_tested=1,
            vulnerabilities=[
                form_parse.RawVulnerability(
                    form_action="https://target.com/search",
                    parameter="endpoint",
                    vulnerability_type="ssrf",
                    payload_used="http://169.254.169.254/latest/meta-data/",
                    snippet="instance-id: i-12345",
                )
            ],
        )
        mock_exec.return_value = mock_raw

        result = tool.run(target="https://target.com/search")
        assert result["vulnerable"] is True
        assert len(result["vulnerabilities"]) == 1

        evidence = tool.extract_evidence({"target": "https://target.com/search"}, result)
        assert evidence is not None
        host, full = evidence
        assert host == "target.com"
        assert full["forms_found"] == 1

        facts = tool.extract_facts({"target": "https://target.com/search"}, result)
        assert len(facts) == 1
        assert facts[0]["host"] == "target.com"
        assert facts[0]["ssrf_vulnerable"] is True
        assert facts[0]["cloud_metadata_exposed"] is True
