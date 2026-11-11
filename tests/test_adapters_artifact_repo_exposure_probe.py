"""
Unit tests for artifact_repo_exposure_probe adapter (execution and parsing).
"""
from unittest.mock import MagicMock, patch

import requests

from tradecraft.adapters.artifact_repo_exposure_probe.execute import (
    ArtifactoryResult,
    ArtifactRepoExposureResult,
    HarborResult,
    NexusResult,
    execute,
    normalize_base_url,
    probe_artifactory,
    probe_harbor,
    probe_nexus,
)
from tradecraft.adapters.artifact_repo_exposure_probe.parse import parse


def _resp(status_code, payload=None, text=None, headers=None):
    r = MagicMock()
    r.status_code = status_code
    r.headers = headers or {}
    r.text = text or ""
    if payload is None:
        r.json.side_effect = ValueError("no json")
    else:
        r.json.return_value = payload
    return r


def test_normalize_base_url():
    assert normalize_base_url("nexus.example.com") == "https://nexus.example.com"
    assert normalize_base_url("https://nexus.example.com/") == "https://nexus.example.com"


# ---------------------------------------------------------------- Nexus


@patch("tradecraft.adapters.artifact_repo_exposure_probe.execute.requests.get")
def test_probe_nexus_vulnerable(mock_get):
    mock_get.side_effect = [
        _resp(200, headers={"Server": "Nexus/3.41.0-01"}),
        _resp(200, {"items": [{"id": "a"}, {"id": "b"}]}),
    ]
    res = probe_nexus("https://nexus.example.com", timeout=5.0)
    assert res.is_nexus is True
    assert res.nexus_version == "3.41.0-01"
    assert res.unauthenticated_access is True
    assert res.vulnerable is True
    assert res.status == "vulnerable"
    assert res.repository_checked == "maven-releases"
    assert res.components_exposed == 2


@patch("tradecraft.adapters.artifact_repo_exposure_probe.execute.requests.get")
def test_probe_nexus_tries_next_repo_after_denied(mock_get):
    mock_get.side_effect = [
        _resp(200, headers={"Server": "Nexus/3.41.0-01"}),
        _resp(403),
        _resp(200, {"items": [{"id": "x"}]}),
    ]
    res = probe_nexus("https://nexus.example.com", timeout=5.0)
    assert res.vulnerable is True
    assert res.repository_checked == "npm-hosted"


@patch("tradecraft.adapters.artifact_repo_exposure_probe.execute.requests.get")
def test_probe_nexus_all_denied(mock_get):
    mock_get.side_effect = [
        _resp(200, headers={"Server": "Nexus/3.41.0-01"}),
        _resp(403), _resp(403), _resp(403),
    ]
    res = probe_nexus("https://nexus.example.com", timeout=5.0)
    assert res.vulnerable is False
    assert res.status == "auth_required"


@patch("tradecraft.adapters.artifact_repo_exposure_probe.execute.requests.get")
def test_probe_nexus_not_nexus(mock_get):
    mock_get.return_value = _resp(200, headers={"Server": "nginx"})
    res = probe_nexus("https://notnexus.example.com", timeout=5.0)
    assert res.is_nexus is False
    assert res.status == "not_nexus"


@patch("tradecraft.adapters.artifact_repo_exposure_probe.execute.requests.get")
def test_probe_nexus_request_error(mock_get):
    mock_get.side_effect = requests.RequestException("refused")
    res = probe_nexus("https://nexus.example.com", timeout=5.0)
    assert res.status == "error"
    assert res.vulnerable is False


# ---------------------------------------------------------------- Artifactory


@patch("tradecraft.adapters.artifact_repo_exposure_probe.execute.requests.get")
def test_probe_artifactory_vulnerable(mock_get):
    mock_get.side_effect = [
        _resp(200, text="OK"),
        _resp(200, [{"key": "libs-release"}, {"key": "libs-snapshot"}]),
    ]
    res = probe_artifactory("https://artifactory.example.com", timeout=5.0)
    assert res.is_artifactory is True
    assert res.unauthenticated_access is True
    assert res.vulnerable is True
    assert res.repositories_exposed == 2
    assert res.repository_names == ["libs-release", "libs-snapshot"]


@patch("tradecraft.adapters.artifact_repo_exposure_probe.execute.requests.get")
def test_probe_artifactory_auth_required(mock_get):
    mock_get.side_effect = [_resp(200, text="OK"), _resp(401)]
    res = probe_artifactory("https://artifactory.example.com", timeout=5.0)
    assert res.connected is True
    assert res.vulnerable is False
    assert res.status == "auth_required"


@patch("tradecraft.adapters.artifact_repo_exposure_probe.execute.requests.get")
def test_probe_artifactory_not_artifactory(mock_get):
    mock_get.return_value = _resp(200, text="pong")
    res = probe_artifactory("https://notartifactory.example.com", timeout=5.0)
    assert res.is_artifactory is False
    assert res.status == "not_artifactory"


# ---------------------------------------------------------------- Harbor


@patch("tradecraft.adapters.artifact_repo_exposure_probe.execute.requests.get")
def test_probe_harbor_over_exposed(mock_get):
    mock_get.side_effect = [
        _resp(200, {"harbor_version": "v2.9.1"}),
        _resp(200, [{"name": "public-proj"}]),
        _resp(200, [{"name": "public-proj"}, {"name": "internal-proj"}, {"name": "secrets-proj"}]),
    ]
    res = probe_harbor("https://harbor.example.com", timeout=5.0)
    assert res.is_harbor is True
    assert res.harbor_version == "v2.9.1"
    assert res.public_project_count == 1
    assert res.unauth_project_count == 3
    assert res.unauthenticated_access is True
    assert res.vulnerable is True
    assert res.status == "vulnerable"


@patch("tradecraft.adapters.artifact_repo_exposure_probe.execute.requests.get")
def test_probe_harbor_no_over_exposure(mock_get):
    mock_get.side_effect = [
        _resp(200, {"harbor_version": "v2.9.1"}),
        _resp(200, [{"name": "public-proj"}]),
        _resp(200, [{"name": "public-proj"}]),
    ]
    res = probe_harbor("https://harbor.example.com", timeout=5.0)
    assert res.vulnerable is False
    assert res.status == "no_over_exposure"


@patch("tradecraft.adapters.artifact_repo_exposure_probe.execute.requests.get")
def test_probe_harbor_unauth_endpoint_requires_auth(mock_get):
    mock_get.side_effect = [
        _resp(200, {"harbor_version": "v2.9.1"}),
        _resp(200, [{"name": "public-proj"}]),
        _resp(401),
    ]
    res = probe_harbor("https://harbor.example.com", timeout=5.0)
    assert res.vulnerable is False
    assert res.status == "no_over_exposure"


@patch("tradecraft.adapters.artifact_repo_exposure_probe.execute.requests.get")
def test_probe_harbor_not_harbor(mock_get):
    mock_get.return_value = _resp(200, {"other": "thing"})
    res = probe_harbor("https://notharbor.example.com", timeout=5.0)
    assert res.is_harbor is False
    assert res.status == "not_harbor"


# ---------------------------------------------------------------- execute() dispatcher


@patch("tradecraft.adapters.artifact_repo_exposure_probe.execute.probe_harbor")
@patch("tradecraft.adapters.artifact_repo_exposure_probe.execute.probe_artifactory")
@patch("tradecraft.adapters.artifact_repo_exposure_probe.execute.probe_nexus")
def test_execute_auto_probes_all_three(mock_nexus, mock_artifactory, mock_harbor):
    mock_nexus.return_value = NexusResult(base_url="https://x", status="not_nexus")
    mock_artifactory.return_value = ArtifactoryResult(base_url="https://x", status="not_artifactory")
    mock_harbor.return_value = HarborResult(base_url="https://x", status="not_harbor")

    out = execute("x.example.com", service="auto")
    mock_nexus.assert_called_once()
    mock_artifactory.assert_called_once()
    mock_harbor.assert_called_once()
    assert out.vulnerable is False


@patch("tradecraft.adapters.artifact_repo_exposure_probe.execute.probe_harbor")
@patch("tradecraft.adapters.artifact_repo_exposure_probe.execute.probe_artifactory")
@patch("tradecraft.adapters.artifact_repo_exposure_probe.execute.probe_nexus")
def test_execute_explicit_harbor_only(mock_nexus, mock_artifactory, mock_harbor):
    mock_harbor.return_value = HarborResult(base_url="https://x", vulnerable=True, status="vulnerable")

    out = execute("x.example.com", service="harbor")
    mock_harbor.assert_called_once()
    mock_nexus.assert_not_called()
    mock_artifactory.assert_not_called()
    assert out.vulnerable is True


def test_execute_invalid_target():
    out = execute("   ")
    assert out.error is not None
    assert out.vulnerable is False


# ---------------------------------------------------------------- parse()


def test_parse_includes_findings_for_vulnerable_services():
    res = ArtifactRepoExposureResult(
        target="x.example.com",
        nexus=NexusResult(
            base_url="https://x", vulnerable=True, status="vulnerable",
            repository_checked="maven-releases", components_exposed=5,
        ),
        artifactory=ArtifactoryResult(base_url="https://x", vulnerable=False, status="auth_required"),
        vulnerable=True,
        summary="Nexus VULNERABLE; Artifactory auth_required",
    )
    out = parse(res)
    assert out["nexus"]["components_exposed"] == 5
    assert out["artifactory"]["vulnerable"] is False
    assert len(out["findings"]) == 1
    assert "Nexus" in out["findings"][0]
