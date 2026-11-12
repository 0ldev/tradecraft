"""Tests for Phase 5: deterministic ATT&CK/CVSS finding mapping."""
from tradecraft.reporting.attack_map import map_finding, render_attack_appendix


def test_sqli_rule_wins_over_generic():
    m = map_finding("FINDING #1: SQL injection on app.local:443 via search param")
    assert m["rule"] == "sql_injection"
    assert m["technique"] == "T1190"
    assert m["cvss_estimated"] == 8.6


def test_command_injection_beats_lower_priority():
    m = map_finding("RCE via deserialization, confirmed with reverse shell")
    assert m["rule"] == "command_injection"
    assert m["cvss_estimated"] == 9.8


def test_credential_exposure():
    m = map_finding("AWS API key leaked in public s3 bucket")
    assert m["technique"] == "T1552"


def test_ad_rule():
    m = map_finding("Kerberoastable accounts found by bloodhound")
    assert m["technique"] == "T1558"


def test_fallback_for_unmatched():
    m = map_finding("Unusual header behavior worth investigating")
    assert m["rule"] == "generic_exploitation"
    assert m["technique"] == "T1190"


def test_appendix_rows_and_estimate_label():
    text = render_attack_appendix([
        "SQL injection on app.local:443",
        "open redirect on 10.0.0.5:80",
    ])
    assert "| Finding | ATT&CK Technique | Est. CVSS |" in text
    assert "T1190" in text and "T1566.002" in text
    assert "(estimated)" in text


def test_appendix_empty():
    assert "nothing to map" in render_attack_appendix([])
