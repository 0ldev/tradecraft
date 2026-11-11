from unittest.mock import patch

from tradecraft.adapters.ssrf_probe.execute import RawSsrfResult, SsrfAttempt
from tradecraft.tools.registry import ALL_TOOLS
from tradecraft.tools.ssrf_probe import SsrfProbe


def test_tool_identity_and_contract():
    tool = SsrfProbe()
    assert tool.tool_id == "ssrf_probe"
    assert tool.spec.name == "ssrf_probe"
    assert tool.scope_param == "target"
    assert tool.destructive is False
    assert tool.required_binary is None
    assert any(t.tool_id == "ssrf_probe" for t in ALL_TOOLS)


def test_run_forwards_all_params_and_returns_parsed_hit():
    tool = SsrfProbe()
    raw = RawSsrfResult(
        target="https://shop.example.com/api/fetch-preview",
        inject_location="header",
        attempts=[SsrfAttempt("aws_imds_v1", "http://169.254.169.254/latest/meta-data/", 200, "ami-id")],
    )
    with patch("tradecraft.adapters.ssrf_probe.execute.execute", return_value=raw) as ex:
        out = tool.run(
            target="https://shop.example.com/api/fetch-preview",
            inject_location="header",
            header_name="X-Forwarded-Host",
            oob_domain="abc123.oast.me",
            timeout=7,
        )
    ex.assert_called_once_with(
        target="https://shop.example.com/api/fetch-preview",
        inject_location="header",
        method="",
        json_body_template="",
        header_name="X-Forwarded-Host",
        oob_domain="abc123.oast.me",
        timeout=7,
    )
    assert out["hits"][0]["preset_label"] == "aws_imds_v1"


def test_run_error_is_reported():
    tool = SsrfProbe()
    raw = RawSsrfResult(target="https://x.example.com", inject_location="json_body",
                        error="json_body_template is required when inject_location is 'json_body'")
    with patch("tradecraft.adapters.ssrf_probe.execute.execute", return_value=raw):
        out = tool.run(target="https://x.example.com", inject_location="json_body")
    assert out["error"].startswith("json_body_template is required")


def test_extract_facts_records_tested_or_vulnerable():
    tool = SsrfProbe()
    # Error case -> empty
    assert tool.extract_facts({"target": "https://x.example.com"}, {"error": "fail"}) == []
    assert tool.extract_facts({}, {}) == []

    clean = tool.extract_facts({"target": "https://x.example.com/api"}, {"reason": "no injected internal URL produced a response"})
    assert clean == [{"host": "x.example.com", "port": 443, "ssrf_tested": True}]

    # Vulnerable
    vuln = tool.extract_facts(
        {"target": "https://x.example.com/api", "inject_location": "header"},
        {"hits": [{"preset_label": "aws_imds_v1"}]},
    )
    assert vuln[0]["ssrf_vulnerable"] is True
    assert "SSRF vulnerability indicated" in vuln[0]["vulnerability"]
    assert vuln[0]["severity"] == "high"
