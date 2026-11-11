"""
Unit tests for AsnDiscovery tool glue.
"""
from unittest.mock import patch

from tradecraft.adapters.asn_discovery.execute import RawAsnResult
from tradecraft.tools.asn_discovery import AsnDiscovery


def test_asn_discovery_run_success():
    tool = AsnDiscovery()
    fake_raw = RawAsnResult(
        org_name="example",
        asns=["AS13335"],
        cidrs=["198.51.100.0/24"],
    )

    with patch("tradecraft.tools.asn_discovery.asn_execute", return_value=fake_raw):
        out = tool.run("example.com")
        assert out["target"] == "example.com"
        assert out["org_name"] == "example"
        assert out["discovered_asns"] == ["AS13335"]
        assert out["discovered_cidrs"] == ["198.51.100.0/24"]


def test_asn_discovery_run_skipped_private():
    tool = AsnDiscovery()
    fake_raw = RawAsnResult(
        org_name="127.0.0.1",
        asns=[],
        cidrs=[],
        skipped_private=True,
    )

    with patch("tradecraft.tools.asn_discovery.asn_execute", return_value=fake_raw):
        out = tool.run("127.0.0.1")
        assert "skipped" in out["note"]
        assert out["discovered_asns"] == []


def test_asn_discovery_extract_evidence_and_facts():
    tool = AsnDiscovery()
    result = {
        "target": "example.com",
        "org_name": "example",
        "discovered_asns": ["AS123"],
        "discovered_cidrs": [],
    }

    ev = tool.extract_evidence({"target": "example.com"}, result)
    assert ev == ("example.com", result)

    facts = tool.extract_facts({"target": "example.com"}, result)
    assert facts == []
