"""
Unit tests for ArtifactRepoExposureProbe tool glue.
"""
from unittest.mock import patch

from tradecraft.adapters.artifact_repo_exposure_probe.execute import ArtifactRepoExposureResult, NexusResult
from tradecraft.tools.artifact_repo_exposure_probe import ArtifactRepoExposureProbe


def _vuln_result():
    return ArtifactRepoExposureResult(
        target="nexus.example.com",
        nexus=NexusResult(
            base_url="https://nexus.example.com", connected=True, vulnerable=True, status="vulnerable",
            nexus_version="3.41.0-01", repository_checked="maven-releases", components_exposed=5,
        ),
        vulnerable=True,
        summary="Nexus VULNERABLE: unauthenticated access",
    )


def test_artifact_repo_exposure_probe_run():
    tool = ArtifactRepoExposureProbe()
    with patch("tradecraft.tools.artifact_repo_exposure_probe.repo_execute", return_value=_vuln_result()):
        out = tool.run("nexus.example.com", service="nexus")
    assert out["vulnerable"] is True
    assert "_full_evidence" in out


def test_extract_evidence_pops_full_evidence():
    tool = ArtifactRepoExposureProbe()
    fake_full = {"vulnerable": False}
    result_dict = {"_full_evidence": fake_full}
    ev = tool.extract_evidence({"target": "nexus.example.com"}, result_dict)
    assert ev == ("nexus.example.com", fake_full)
    assert "_full_evidence" not in result_dict


def test_extract_facts_nexus_vulnerable_is_high():
    tool = ArtifactRepoExposureProbe()
    res = {"nexus": {"connected": True, "vulnerable": True, "nexus_version": "3.41.0-01"}}
    facts = tool.extract_facts({"target": "nexus.example.com"}, res)
    assert len(facts) == 1
    assert facts[0]["service"] == "nexus"
    assert facts[0]["severity"] == "high"


def test_extract_facts_harbor_vulnerable_is_high():
    tool = ArtifactRepoExposureProbe()
    res = {"harbor": {"connected": True, "vulnerable": True, "harbor_version": "v2.9.1"}}
    facts = tool.extract_facts({"target": "harbor.example.com"}, res)
    assert len(facts) == 1
    assert facts[0]["service"] == "harbor"
    assert facts[0]["severity"] == "high"
