from unittest.mock import patch

from tradecraft.adapters.email_auth_posture.execute import RawEmailAuthResult
from tradecraft.tools.email_auth_posture import EmailAuthPosture


def test_tool_attributes():
    tool = EmailAuthPosture()
    assert tool.tool_id == "email_auth_posture"
    assert tool.spec.name == "email_auth_posture"
    assert tool.scope_param == "target"


def test_tool_run_success():
    tool = EmailAuthPosture()
    mock_raw = RawEmailAuthResult(
        target="exampleauto.com.br",
        spf_txt_records=["v=spf1 include:_spf.google.com ~all"],
        dmarc_txt_records=["v=DMARC1; p=none"],
        dkim_hits={"google": ["v=DKIM1; ..."]},
    )
    with patch("tradecraft.adapters.email_auth_posture.execute.execute", return_value=mock_raw):
        res = tool.run(target="exampleauto.com.br")

        assert res["target"] == "exampleauto.com.br"
        assert res["spf"]["present"] is True
        assert res["spf"]["strength"] == "weak"
        assert res["dmarc"]["present"] is True
        assert res["dmarc"]["strength"] == "weak"
        assert "_full_evidence" in res


def test_tool_run_error():
    tool = EmailAuthPosture()
    mock_raw = RawEmailAuthResult(error="network failure")
    with patch("tradecraft.adapters.email_auth_posture.execute.execute", return_value=mock_raw):
        res = tool.run(target="exampleauto.com.br")
        assert res["error"] == "network failure"


def test_extract_facts_vulnerabilities():
    tool = EmailAuthPosture()
    params = {"target": "https://example.com.br"}

    # Case 1: Missing SPF and missing DMARC
    res_missing = {
        "target": "example.com.br",
        "spf": {"present": False, "strength": "missing"},
        "dmarc": {"present": False, "strength": "missing"},
        "dkim": {"selectors_found": []},
        "evidence_id": "email_auth_posture:example.com.br",
    }
    facts = tool.extract_facts(params, res_missing)
    assert len(facts) == 2
    assert any("No SPF" in f["vulnerability"] and f["severity"] == "medium" for f in facts)
    assert any("No DMARC" in f["vulnerability"] and f["severity"] == "medium" for f in facts)
    assert all(f["host"] == "example.com.br" and f["port"] == 25 for f in facts)
    assert all(f["evidence"] == "email_auth_posture:example.com.br" for f in facts)

    # Case 2: Permissive SPF and weak DMARC (p=none)
    res_weak = {
        "target": "example.com.br",
        "spf": {"present": True, "strength": "permissive", "record": "v=spf1 +all"},
        "dmarc": {"present": True, "strength": "weak", "record": "v=DMARC1; p=none"},
    }
    facts_weak = tool.extract_facts(params, res_weak)
    assert len(facts_weak) == 2
    assert any("Permissive SPF" in f["vulnerability"] and f["severity"] == "medium" for f in facts_weak)
    assert any("p=none" in f["vulnerability"] and f["severity"] == "low" for f in facts_weak)

    # Case 3: Strict SPF, strict DMARC, enforced MTA-STS -> 0 facts
    res_clean = {
        "target": "example.com.br",
        "spf": {"present": True, "strength": "strict", "record": "v=spf1 -all"},
        "dmarc": {"present": True, "strength": "strict", "record": "v=DMARC1; p=reject"},
        "mta_sts": {"present": True, "mode": "enforce"},
    }
    facts_clean = tool.extract_facts(params, res_clean)
    assert facts_clean == []

    res_missing_mta = {
        "target": "example.com.br",
        "spf": {"present": True, "strength": "strict", "record": "v=spf1 -all"},
        "dmarc": {"present": True, "strength": "strict", "record": "v=DMARC1; p=reject"},
        "mta_sts": {"present": False, "mode": "missing"},
    }
    facts_mta = tool.extract_facts(params, res_missing_mta)
    assert len(facts_mta) == 1
    assert "No MTA-STS record" in facts_mta[0]["vulnerability"]
    assert facts_mta[0]["severity"] == "low"

    res_testing_mta = {
        "target": "example.com.br",
        "mta_sts": {"present": True, "mode": "testing"},
    }
    facts_testing = tool.extract_facts(params, res_testing_mta)
    assert len(facts_testing) == 1
    assert "testing mode" in facts_testing[0]["vulnerability"]
    assert facts_testing[0]["severity"] == "low"


def test_extract_evidence():
    tool = EmailAuthPosture()
    params = {"target": "https://example.com.br/admin"}
    result = {
        "target": "example.com.br",
        "spf": {"present": True},
        "_full_evidence": {"target": "example.com.br", "spf": {"present": True}},
    }
    extracted = tool.extract_evidence(params, result)
    assert extracted is not None
    target_key, full = extracted
    assert target_key == "example.com.br"
    assert "_full_evidence" not in result
