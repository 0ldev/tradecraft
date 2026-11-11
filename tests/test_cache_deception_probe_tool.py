from unittest.mock import patch

from tradecraft.adapters.cache_deception_probe.execute import DeceptionAttempt
from tradecraft.adapters.http_request.parse import evidence_target_from_url
from tradecraft.tools.cache_deception_probe import CacheDeceptionProbe

TARGET = "https://www.example.com/account/settings"
MARKER = "alice@example.com"


def _attempt(suffix: str, confirmed: bool) -> DeceptionAttempt:
    return DeceptionAttempt(
        suffix=suffix,
        crafted_url=f"{TARGET}{suffix}",
        authed_status=200,
        authed_body=f"Welcome {MARKER}",
        authed_marker_found=True,
        clean_status=200,
        clean_body=f"Welcome {MARKER}" if confirmed else "Login",
        clean_marker_found=confirmed,
        deception_confirmed=confirmed,
    )


def test_run_passes_params_through_to_execute():
    tool = CacheDeceptionProbe()
    with patch("tradecraft.tools.cache_deception_probe.cd_execute.execute", return_value=[_attempt("/nonexistent.css", False)]) as mock_exec:
        tool.run(target=TARGET, success_marker=MARKER, auth_headers="Cookie: s=1", timeout=7)
    kwargs = mock_exec.call_args.kwargs
    assert kwargs == {
        "target": TARGET,
        "success_marker": MARKER,
        "auth_headers": "Cookie: s=1",
        "timeout": 7,
    }


def test_extract_facts_vulnerable_returns_high_severity_fact():
    tool = CacheDeceptionProbe()
    attempts = [_attempt("/nonexistent.css", True), _attempt("/nonexistent.js", False)]
    with patch("tradecraft.tools.cache_deception_probe.cd_execute.execute", return_value=attempts):
        res = tool.run(target=TARGET, success_marker=MARKER, auth_headers="Cookie: s=1")
    params = {"target": TARGET}
    facts = tool.extract_facts(params, res)
    assert len(facts) == 1
    fact = facts[0]
    assert fact["severity"] == "high"
    assert fact["host"] == "www.example.com"
    assert fact["port"] == 443
    assert "/nonexistent.css" in fact["vulnerability"]
    assert "/nonexistent.js" not in fact["vulnerability"]


def test_extract_facts_not_vulnerable_returns_empty():
    tool = CacheDeceptionProbe()
    attempts = [_attempt("/nonexistent.css", False)]
    with patch("tradecraft.tools.cache_deception_probe.cd_execute.execute", return_value=attempts):
        res = tool.run(target=TARGET, success_marker=MARKER, auth_headers="Cookie: s=1")
    assert tool.extract_facts({"target": TARGET}, res) == []


def test_extract_evidence_pops_full_evidence():
    tool = CacheDeceptionProbe()
    attempts = [_attempt("/nonexistent.css", True)]
    with patch("tradecraft.tools.cache_deception_probe.cd_execute.execute", return_value=attempts):
        res = tool.run(target=TARGET, success_marker=MARKER, auth_headers="Cookie: s=1")
    out = tool.extract_evidence({"target": TARGET}, res)
    assert out is not None
    target, full = out
    assert target == evidence_target_from_url(TARGET)
    assert target == "www.example.com/account/settings"
    assert "_full_evidence" not in res
    assert full["attempts"][0]["authed_body"] == f"Welcome {MARKER}"
    assert full["attempts"][0]["clean_body"] == f"Welcome {MARKER}"


def test_extract_evidence_none_when_missing():
    tool = CacheDeceptionProbe()
    assert tool.extract_evidence({"target": TARGET}, {"vulnerable": False}) is None
