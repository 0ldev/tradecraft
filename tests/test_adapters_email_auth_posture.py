from unittest.mock import patch

from tradecraft.adapters.dnsx.execute import RawDnsxResult
from tradecraft.adapters.email_auth_posture.execute import (
    DEFAULT_DKIM_SELECTORS,
    RawEmailAuthResult,
    execute,
    normalize_domain,
)
from tradecraft.adapters.email_auth_posture.parse import (
    parse_result,
    score_dmarc,
    score_mta_sts,
    score_spf,
    score_tls_rpt,
    summarize_dkim,
)


def test_normalize_domain():
    assert normalize_domain("exampleauto.com.br") == "exampleauto.com.br"
    assert normalize_domain("https://example.com.br/path/login") == "example.com.br"
    assert normalize_domain("examplepaint.com.br:8443") == "examplepaint.com.br"
    assert normalize_domain("") == ""


def test_execute_dnsx_invocation_and_mapping():
    dnsx_stdout = """{"host":"example.com","txt":["v=spf1 include:_spf.google.com ~all"],"status_code":"NOERROR"}
{"host":"_dmarc.example.com","txt":["v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@example.com"],"status_code":"NOERROR"}
{"host":"google._domainkey.example.com","txt":["v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3..."],"status_code":"NOERROR"}
{"host":"_mta-sts.example.com","txt":["v=STSv1; id=20261102;"],"status_code":"NOERROR"}
{"host":"_smtp._tls.example.com","txt":["v=TLSRPTv1; rua=mailto:tls-rpt@example.com;"],"status_code":"NOERROR"}
"""

    with patch("tradecraft.adapters.dnsx.execute.execute") as mock_dnsx:
        mock_dnsx.return_value = RawDnsxResult(stdout=dnsx_stdout, returncode=0)
        res = execute("example.com")

        assert mock_dnsx.called
        target_arg = mock_dnsx.call_args[1].get("target") or mock_dnsx.call_args[0][0]
        assert "example.com" in target_arg
        assert "_dmarc.example.com" in target_arg
        assert "_mta-sts.example.com" in target_arg
        assert "_smtp._tls.example.com" in target_arg
        assert "google._domainkey.example.com" in target_arg

        assert res.target == "example.com"
        assert res.spf_txt_records == ["v=spf1 include:_spf.google.com ~all"]
        assert res.dmarc_txt_records == ["v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@example.com"]
        assert res.mta_sts_txt_records == ["v=STSv1; id=20261102;"]
        assert res.tls_rpt_txt_records == ["v=TLSRPTv1; rua=mailto:tls-rpt@example.com;"]
        assert "google" in res.dkim_hits
        assert res.dkim_hits["google"] == ["v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3..."]
        assert res.error is None


def test_execute_custom_dkim_selectors():
    with patch("tradecraft.adapters.dnsx.execute.execute") as mock_dnsx:
        mock_dnsx.return_value = RawDnsxResult(stdout="", returncode=0)
        execute("example.com", dkim_selectors=["s1", "s2"])

        target_arg = mock_dnsx.call_args[1].get("target") or mock_dnsx.call_args[0][0]
        assert "s1._domainkey.example.com" in target_arg
        assert "s2._domainkey.example.com" in target_arg
        # Default should not be present
        assert "google._domainkey.example.com" not in target_arg


def test_execute_dnsx_error():
    with patch("tradecraft.adapters.dnsx.execute.execute") as mock_dnsx:
        mock_dnsx.return_value = RawDnsxResult(error="dnsx binary missing")
        res = execute("example.com")
        assert res.error == "dnsx binary missing"


def test_score_spf_missing():
    res = score_spf([])
    assert res == {"present": False, "strength": "missing"}


def test_score_spf_strict():
    res = score_spf(["v=spf1 ip4:192.0.2.0/24 -all"])
    assert res["present"] is True
    assert res["strength"] == "strict"
    assert res["record"] == "v=spf1 ip4:192.0.2.0/24 -all"


def test_score_spf_weak():
    # Real captured SPF from exampleauto / example
    raw = "v=spf1 include:_spf.rdstation.com.br include:_spf.google.com ~all"
    res = score_spf([raw])
    assert res["present"] is True
    assert res["strength"] == "weak"


def test_score_spf_permissive_and_multiple():
    res_plus = score_spf(["v=spf1 +all"])
    assert res_plus["strength"] == "permissive"

    res_q = score_spf(["v=spf1 ?all"])
    assert res_q["strength"] == "permissive"

    res_no_qual = score_spf(["v=spf1 ip4:10.0.0.1 all"])
    assert res_no_qual["strength"] == "permissive"

    res_no_all = score_spf(["v=spf1 include:mail.example.com"])
    assert res_no_all["strength"] == "permissive"

    res_mult = score_spf(["v=spf1 -all", "v=spf1 ~all"])
    assert res_mult["strength"] == "strict"
    assert "multiple SPF records" in res_mult["note"]


def test_score_dmarc_missing():
    res = score_dmarc([])
    assert res == {"present": False, "strength": "missing"}

    # Irrelevant TXT record on _dmarc host
    res_junk = score_dmarc(["some-other-verification=12345"])
    assert res_junk == {"present": False, "strength": "missing"}


def test_score_dmarc_policies():
    strict = score_dmarc(["v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@org.com"])
    assert strict["present"] is True
    assert strict["strength"] == "strict"
    assert strict["pct"] == 100

    quarantine = score_dmarc(["v=DMARC1; p=quarantine; pct=20;"])
    assert quarantine["present"] is True
    assert quarantine["strength"] == "moderate"
    assert quarantine["pct"] == 20

    none_policy = score_dmarc(["v=DMARC1; p=none; sp=none"])
    assert none_policy["present"] is True
    assert none_policy["strength"] == "weak"
    assert none_policy["pct"] is None


def test_score_mta_sts():
    missing = score_mta_sts([])
    assert missing["present"] is False
    assert missing["mode"] == "missing"

    # Present without policy file
    dns_only = score_mta_sts(["v=STSv1; id=20261102;"])
    assert dns_only["present"] is True
    assert dns_only["id"] == "20261102"
    assert dns_only["mode"] == "unknown"

    policy_text = "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400\n"
    enforce = score_mta_sts(["v=STSv1; id=20261102;"], policy_file=policy_text)
    assert enforce["present"] is True
    assert enforce["mode"] == "enforce"
    assert enforce["max_age"] == 86400
    assert enforce["mx"] == ["mail.example.com"]
    assert enforce["policy_file_present"] is True


def test_score_tls_rpt():
    missing = score_tls_rpt([])
    assert missing["present"] is False

    present = score_tls_rpt(["v=TLSRPTv1; rua=mailto:tls-reports@example.com"])
    assert present["present"] is True
    assert present["rua"] == "mailto:tls-reports@example.com"


def test_summarize_dkim():
    summary = summarize_dkim({"selector1": ["k=rsa..."], "google": ["v=DKIM1..."]})
    assert summary["selectors_found"] == ["google", "selector1"]
    assert summary["conclusive"] is False
    assert "absence at these selectors" in summary["note"]


def test_parse_result():
    raw = RawEmailAuthResult(
        target="target.com",
        spf_txt_records=["v=spf1 -all"],
        dmarc_txt_records=["v=DMARC1; p=reject"],
        dkim_hits={"default": ["txt"]},
        mta_sts_txt_records=["v=STSv1; id=1;"],
        tls_rpt_txt_records=["v=TLSRPTv1; rua=mailto:r@target.com"],
    )
    res = parse_result(raw, "target.com")
    assert res["target"] == "target.com"
    assert res["spf"]["strength"] == "strict"
    assert res["dmarc"]["strength"] == "strict"
    assert res["dkim"]["selectors_found"] == ["default"]
    assert res["mta_sts"]["present"] is True
    assert res["tls_rpt"]["present"] is True
