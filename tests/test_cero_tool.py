"""
Unit tests for Cero tool glue.
"""
from unittest.mock import patch

from tradecraft.adapters.cero.execute import RawCeroResult
from tradecraft.tools.cero import Cero


def test_cero_run_success():
    tool = Cero()
    fake_raw = RawCeroResult(domains=["*.example.com", "api.example.com", "example.com"])

    with patch("tradecraft.tools.cero.cero_execute", return_value=fake_raw):
        out = tool.run("example.com")
        assert out["target"] == "example.com"
        assert out["domains_found"] == 2
        assert "api.example.com" in out["domains"]


def test_cero_run_error():
    tool = Cero()
    fake_raw = RawCeroResult(domains=[], error="binary not found")

    with patch("tradecraft.tools.cero.cero_execute", return_value=fake_raw):
        out = tool.run("example.com")
        assert out["error"] == "binary not found"
        assert out["domains"] == []


def test_cero_extract_evidence_and_facts():
    tool = Cero()
    result = {"target": "example.com", "domains_found": 1, "domains": ["api.example.com"]}

    ev = tool.extract_evidence({"target": "example.com"}, result)
    assert ev == ("example.com", result)

    facts = tool.extract_facts({"target": "example.com"}, result)
    assert facts == []
