"""
Unit tests for the response_security_audit tool layer. Merges the former
cookie_security_check/security_header_check/sri_check tool-test suites --
all real regression cases from those files are preserved here unchanged.
"""
from __future__ import annotations

from unittest.mock import patch

from tradecraft.adapters.response_security_audit.execute import RawResponseAuditResult
from tradecraft.tools.response_security_audit import ResponseSecurityAudit


def test_tool_attributes():
    tool = ResponseSecurityAudit()
    assert tool.tool_id == "response_security_audit"
    assert tool.spec.name == "response_security_audit"
    assert tool.scope_param == "target"
    assert tool.destructive is False


def test_run_error_is_reported_not_as_clean_results():
    tool = ResponseSecurityAudit()
    failed = RawResponseAuditResult(target="https://down.example", error="Connection refused")
    with patch("tradecraft.tools.response_security_audit.audit_execute.execute", return_value=failed):
        result = tool.run(target="https://down.example")
    assert result["error"] == "Connection refused"
    assert "missing_headers" not in result
    assert "cookies" not in result
    assert "sri_total_assets_scanned" not in result


def test_run_success_combines_all_three_and_builds_evidence():
    tool = ResponseSecurityAudit()
    raw = RawResponseAuditResult(
        target="https://target.com/login",
        final_url="https://target.com/login",
        is_https=True,
        headers={"x-content-type-options": "nosniff"},
        set_cookie_lines=["PHPSESSID=12345; path=/; HttpOnly"],
        body='<script src="https://cdn.external.com/lib.js"></script>',
    )
    with patch("tradecraft.tools.response_security_audit.audit_execute.execute", return_value=raw):
        res = tool.run("https://target.com/login")

    assert res["target"] == "https://target.com/login"
    assert res["cookies_found"] == 1
    assert res["cookies"][0]["name"] == "PHPSESSID"
    assert "missing Secure flag" in res["cookies"][0]["issues"]
    assert res["headers_checked"] == 6
    assert res["sri_total_assets_scanned"] == 1
    assert res["sri_cross_origin_missing_integrity_count"] == 1
    assert "_full_evidence" in res


def test_run_caps_long_sri_list_and_notes_it():
    tool = ResponseSecurityAudit()
    body = "".join(f'<script src="https://cdn{i}.example.com/a.js"></script>' for i in range(20))
    raw = RawResponseAuditResult(
        target="https://target.com", final_url="https://target.com/", is_https=True, body=body,
    )
    with patch("tradecraft.tools.response_security_audit.audit_execute.execute", return_value=raw):
        res = tool.run("https://target.com")

    assert len(res["sri_cross_origin_missing_integrity"]) == 15
    assert res["sri_omitted_assets"] == 5
    assert "omitted to conserve context" in res["sri_note"]


def test_extract_evidence_pops_full_evidence():
    tool = ResponseSecurityAudit()
    params = {"target": "https://target.com/login"}
    result = {
        "target": "https://target.com/login",
        "final_url": "https://target.com/login",
        "cookies": [],
        "_full_evidence": {"raw": "data"},
    }
    extracted = tool.extract_evidence(params, result)
    assert extracted is not None
    target_key, full = extracted
    assert target_key == "target.com"
    assert "_full_evidence" not in result


def test_extract_evidence_none_without_full_evidence():
    tool = ResponseSecurityAudit()
    assert tool.extract_evidence({"target": "https://target.com"}, {"final_url": "https://target.com/"}) is None


# ---------------------------------------------------------------- extract_facts: cookies


def test_extract_facts_cookie_session_cookie_is_medium():
    tool = ResponseSecurityAudit()
    params = {"target": "https://target.com/login"}
    result = {
        "final_url": "https://target.com/login",
        "evidence_id": "response_security_audit:target.com",
        "cookies": [
            {"name": "session_id", "is_session_cookie": True, "issues": ["missing Secure flag", "missing HttpOnly flag"]},
            {"name": "view_mode", "is_session_cookie": False, "issues": []},
        ],
    }
    facts = tool.extract_facts(params, result)
    cookie_facts = [f for f in facts if "session_id" in f.get("vulnerability", "")]
    assert len(cookie_facts) == 1
    f = cookie_facts[0]
    assert f["host"] == "target.com"
    assert f["port"] == 443
    assert "missing Secure flag" in f["vulnerability"]
    assert f["severity"] == "medium"
    assert f["evidence"] == "response_security_audit:target.com"


def test_extract_facts_includes_non_session_named_cookie_with_issues():
    # Real captured case: example.com's admin session cookie
    # CA_PIN_ADMIN has neither Secure nor HttpOnly, but its name matches
    # none of the known session-name markers. It must still become a Fact
    # (at "low" severity, since is_session_cookie is False) instead of
    # being silently dropped.
    tool = ResponseSecurityAudit()
    params = {"target": "https://example.com/admin"}
    result = {
        "final_url": "https://example.com/admin",
        "evidence_id": "response_security_audit:example.com",
        "cookies": [
            {"name": "CA_PIN_ADMIN", "is_session_cookie": False, "issues": ["missing Secure flag", "missing HttpOnly flag", "missing SameSite attribute"]},
        ],
    }
    facts = tool.extract_facts(params, result)
    assert len(facts) == 1
    f = facts[0]
    assert f["host"] == "example.com"
    assert "CA_PIN_ADMIN" in f["vulnerability"]
    assert "missing Secure flag" in f["vulnerability"]
    assert f["severity"] == "low"
    assert f["evidence"] == "response_security_audit:example.com"


# ---------------------------------------------------------------- extract_facts: headers


def test_extract_facts_header_fact_is_low():
    tool = ResponseSecurityAudit()
    params = {"target": "https://example.com"}
    result = {
        "final_url": "https://example.com/",
        "missing_headers": ["permissions-policy"],
        "weak_headers": [{"header": "x-frame-options", "value": "ALLOW-FROM x", "issues": ["bad"]}],
        "evidence_id": "response_security_audit:example.com",
    }
    facts = tool.extract_facts(params, result)
    header_facts = [f for f in facts if "permissions-policy" in f.get("vulnerability", "")]
    assert len(header_facts) == 1
    f = header_facts[0]
    assert f["host"] == "example.com"
    assert f["port"] == 443
    assert f["severity"] == "low"
    assert "x-frame-options" in f["vulnerability"]
    assert f["evidence"] == "response_security_audit:example.com"


# ---------------------------------------------------------------- extract_facts: SRI


def test_extract_facts_sri_fact_is_low():
    tool = ResponseSecurityAudit()
    params = {"target": "https://target.com"}
    result = {
        "final_url": "https://target.com/",
        "sri_cross_origin_missing_integrity_count": 3,
        "evidence_id": "response_security_audit:target.com",
    }
    facts = tool.extract_facts(params, result)
    sri_facts = [f for f in facts if "cross-origin script" in f.get("vulnerability", "")]
    assert len(sri_facts) == 1
    assert sri_facts[0]["host"] == "target.com"
    assert sri_facts[0]["port"] == 443
    assert "3 cross-origin script(s)/stylesheet(s)" in sri_facts[0]["vulnerability"]
    assert sri_facts[0]["severity"] == "low"
    assert sri_facts[0]["evidence"] == "response_security_audit:target.com"


# ---------------------------------------------------------------- extract_facts: combined/clean


def test_extract_facts_none_on_error_or_fully_clean():
    tool = ResponseSecurityAudit()
    params = {"target": "https://example.com"}
    assert tool.extract_facts(params, {"error": "boom"}) == []
    assert tool.extract_facts(params, {
        "final_url": "https://example.com/", "cookies": [], "missing_headers": [], "weak_headers": [],
        "sri_cross_origin_missing_integrity_count": 0,
    }) == []


def test_extract_facts_returns_all_three_findings_at_once():
    # A single response can trip all three checks simultaneously -- this
    # is the whole point of merging the three fetches into one.
    tool = ResponseSecurityAudit()
    params = {"target": "https://target.com/login"}
    result = {
        "final_url": "https://target.com/login",
        "evidence_id": "response_security_audit:target.com",
        "cookies": [{"name": "session_id", "is_session_cookie": True, "issues": ["missing Secure flag"]}],
        "missing_headers": ["x-frame-options"],
        "weak_headers": [],
        "sri_cross_origin_missing_integrity_count": 2,
    }
    facts = tool.extract_facts(params, result)
    assert len(facts) == 3
    assert {f["severity"] for f in facts} == {"medium", "low"}
