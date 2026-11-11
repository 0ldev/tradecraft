"""
Unit tests for SmtpProbe tool glue.
"""
from unittest.mock import patch

from tradecraft.adapters.smtp_probe.execute import SmtpResult
from tradecraft.tools.smtp_probe import SmtpProbe


def test_smtp_probe_run():
    tool = SmtpProbe()
    fake_res = SmtpResult(
        target="mail.example.com",
        host="mail.example.com",
        port=25,
        connected=True,
        banner="220 mail.example.com ESMTP Exim 4.96",
        software="Exim 4.96",
        extensions=["STARTTLS", "SIZE 52428800"],
        starttls_advertised=True,
        starttls_active=True,
        vrfy_tested=True,
        vrfy_code=252,
        user_enumeration_oracle=False,
    )

    with patch("tradecraft.tools.smtp_probe.smtp_execute", return_value=fake_res):
        out = tool.run("mail.example.com")
        assert out["connected"] is True
        assert out["software"] == "Exim 4.96"
        assert "_full_evidence" in out


def test_smtp_probe_extract_evidence():
    tool = SmtpProbe()
    fake_full = {"connected": True, "software": "Exim"}
    result_dict = {"_full_evidence": fake_full, "host": "mail.example.com"}

    ev = tool.extract_evidence({"target": "mail.example.com"}, result_dict)
    assert ev is not None
    assert ev[0] == "mail.example.com"
    assert ev[1] == fake_full
    assert "_full_evidence" not in result_dict


def test_smtp_probe_extract_facts():
    tool = SmtpProbe()

    # VRFY oracle confirmed
    res = {
        "host": "mail.example.com",
        "port": 25,
        "connected": True,
        "software": "Exim 4.96",
        "banner": "220 mail.example.com ESMTP",
        "starttls": {"active": True},
        "vrfy": {"user_enumeration_oracle": True},
    }
    facts = tool.extract_facts({"target": "mail.example.com"}, res)
    assert len(facts) == 2

    base_fact = facts[0]
    assert base_fact["service"] == "smtp"
    assert base_fact["version"] == "Exim 4.96"
    assert base_fact["starttls"] is True

    vuln_fact = facts[1]
    assert vuln_fact["severity"] == "medium"
    assert "User Enumeration" in vuln_fact["vulnerability"]
