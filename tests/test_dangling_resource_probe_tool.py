from unittest.mock import MagicMock, patch

from tradecraft.adapters.dangling_resource_probe.execute import RawDanglingResult
from tradecraft.tools.dangling_resource_probe import DanglingResourceProbe

EXECUTE_PATH = "tradecraft.tools.dangling_resource_probe.run_dangling_probe"


def _raw(**kwargs) -> RawDanglingResult:
    base = dict(
        target="forgotten.example.com",
        host="forgotten.example.com",
        status_code=404,
        matched_provider="github_pages",
        matched_signature="There isn't a GitHub Pages site here.",
        body_snippet="There isn't a GitHub Pages site here.",
    )
    base.update(kwargs)
    return RawDanglingResult(**base)


def test_extract_facts_dangling_returns_high_severity_fact():
    tool = DanglingResourceProbe()
    result = {"host": "forgotten.example.com", "dangling": True, "matched_provider": "github_pages"}
    facts = tool.extract_facts({"target": "forgotten.example.com"}, result)
    assert len(facts) == 1
    fact = facts[0]
    assert fact["host"] == "forgotten.example.com"
    assert fact["port"] == 443
    assert fact["severity"] == "high"
    assert "github_pages" in fact["vulnerability"]


def test_extract_facts_not_dangling_returns_empty():
    tool = DanglingResourceProbe()
    result = {"host": "forgotten.example.com", "dangling": False, "matched_provider": None}
    assert tool.extract_facts({"target": "forgotten.example.com"}, result) == []


def test_extract_evidence_pops_full_and_returns_host():
    tool = DanglingResourceProbe()
    full = {"target": "forgotten.example.com", "host": "forgotten.example.com", "body_snippet": "x"}
    result = {"host": "forgotten.example.com", "dangling": True, "_full_evidence": full}
    out = tool.extract_evidence({"target": "forgotten.example.com"}, result)
    assert out == ("forgotten.example.com", full)
    assert "_full_evidence" not in result


def test_extract_evidence_none_when_missing():
    tool = DanglingResourceProbe()
    result = {"host": "forgotten.example.com", "dangling": False}
    assert tool.extract_evidence({"target": "forgotten.example.com"}, result) is None


def test_run_passes_target_and_timeout_through():
    tool = DanglingResourceProbe()
    with patch(EXECUTE_PATH, return_value=_raw()) as execute:
        out = tool.run(target="forgotten.example.com", timeout=7)
    execute.assert_called_once_with(target="forgotten.example.com", timeout=7)
    assert out["dangling"] is True
    assert out["matched_provider"] == "github_pages"
    assert out["_full_evidence"]["body_snippet"].startswith("There isn't")


def test_run_default_timeout_is_ten():
    tool = DanglingResourceProbe()
    mock = MagicMock(return_value=_raw())
    with patch(EXECUTE_PATH, mock):
        tool.run(target="forgotten.example.com")
    assert mock.call_args.kwargs == {"target": "forgotten.example.com", "timeout": 10}
