"""
Unit tests for CicdExposureProbe tool glue.
"""
from unittest.mock import patch

from tradecraft.adapters.cicd_exposure_probe.execute import ArgoCdResult, CicdExposureResult, TeamCityResult
from tradecraft.tools.cicd_exposure_probe import CicdExposureProbe


def _vuln_result():
    return CicdExposureResult(
        target="argocd.example.com",
        argocd=ArgoCdResult(
            base_url="https://argocd.example.com", connected=True, vulnerable=True,
            status="vulnerable", argocd_version="v2.9.3", applications_exposed=2,
            application_names=["prod-api", "prod-web"],
        ),
        vulnerable=True,
        summary="Argo CD VULNERABLE: unauthenticated access",
    )


def test_cicd_exposure_probe_run():
    tool = CicdExposureProbe()
    with patch("tradecraft.tools.cicd_exposure_probe.cicd_execute", return_value=_vuln_result()):
        out = tool.run("argocd.example.com", service="argocd")
    assert out["vulnerable"] is True
    assert "_full_evidence" in out


def test_extract_evidence_pops_full_evidence():
    tool = CicdExposureProbe()
    fake_full = {"vulnerable": False, "summary": "clean"}
    result_dict = {"_full_evidence": fake_full}
    ev = tool.extract_evidence({"target": "argocd.example.com"}, result_dict)
    assert ev is not None
    assert ev[0] == "argocd.example.com"
    assert ev[1] == fake_full
    assert "_full_evidence" not in result_dict


def test_extract_evidence_none_when_missing():
    tool = CicdExposureProbe()
    assert tool.extract_evidence({"target": "argocd.example.com"}, {}) is None


def test_extract_facts_argocd_vulnerable_is_high():
    tool = CicdExposureProbe()
    res = {"argocd": {"connected": True, "vulnerable": True, "argocd_version": "v2.9.3"}}
    facts = tool.extract_facts({"target": "argocd.example.com"}, res)
    assert len(facts) == 1
    assert facts[0]["service"] == "argocd"
    assert facts[0]["severity"] == "high"
    assert facts[0]["version"] == "v2.9.3"


def test_extract_facts_teamcity_vulnerable_is_high():
    tool = CicdExposureProbe()
    res = {"teamcity": {"connected": True, "vulnerable": True, "teamcity_version": "2023.11.3"}}
    facts = tool.extract_facts({"target": "ci.example.com"}, res)
    assert len(facts) == 1
    assert facts[0]["service"] == "teamcity"
    assert facts[0]["severity"] == "high"


def test_extract_facts_neither_connected_emits_nothing():
    tool = CicdExposureProbe()
    assert tool.extract_facts({"target": "x.example.com"}, {}) == []
