"""
Unit tests for cicd_exposure_probe adapter (execution and parsing).
"""
from unittest.mock import MagicMock, patch

import requests

from tradecraft.adapters.cicd_exposure_probe.execute import (
    ArgoCdResult,
    CicdExposureResult,
    TeamCityResult,
    execute,
    normalize_base_url,
    probe_argocd,
    probe_teamcity,
)
from tradecraft.adapters.cicd_exposure_probe.parse import parse


def _resp(status_code, payload=None):
    r = MagicMock()
    r.status_code = status_code
    if payload is None:
        r.json.side_effect = ValueError("no json")
    else:
        r.json.return_value = payload
    return r


def test_normalize_base_url():
    assert normalize_base_url("argocd.example.com") == "https://argocd.example.com"
    assert normalize_base_url("https://argocd.example.com/") == "https://argocd.example.com"
    assert normalize_base_url("  ") == ""


# ---------------------------------------------------------------- Argo CD


@patch("tradecraft.adapters.cicd_exposure_probe.execute.requests.get")
def test_probe_argocd_vulnerable(mock_get):
    mock_get.side_effect = [
        _resp(200, {"Version": "v2.9.3"}),
        _resp(200, {"items": [
            {"metadata": {"name": "prod-api"}},
            {"metadata": {"name": "prod-web"}},
        ]}),
    ]
    res = probe_argocd("https://argocd.example.com", timeout=5.0)
    assert res.is_argocd is True
    assert res.argocd_version == "v2.9.3"
    assert res.unauthenticated_access is True
    assert res.vulnerable is True
    assert res.status == "vulnerable"
    assert res.applications_exposed == 2
    assert res.application_names == ["prod-api", "prod-web"]


@patch("tradecraft.adapters.cicd_exposure_probe.execute.requests.get")
def test_probe_argocd_auth_required(mock_get):
    mock_get.side_effect = [
        _resp(200, {"Version": "v2.9.3"}),
        _resp(401),
    ]
    res = probe_argocd("https://argocd.example.com", timeout=5.0)
    assert res.connected is True
    assert res.status == "auth_required"
    assert res.vulnerable is False


@patch("tradecraft.adapters.cicd_exposure_probe.execute.requests.get")
def test_probe_argocd_not_argocd(mock_get):
    mock_get.return_value = _resp(200, {"other": "thing"})
    res = probe_argocd("https://notargocd.example.com", timeout=5.0)
    assert res.is_argocd is False
    assert res.status == "not_argocd"


@patch("tradecraft.adapters.cicd_exposure_probe.execute.requests.get")
def test_probe_argocd_request_error(mock_get):
    mock_get.side_effect = requests.RequestException("connection reset")
    res = probe_argocd("https://argocd.example.com", timeout=5.0)
    assert res.status == "error"
    assert res.vulnerable is False


# ---------------------------------------------------------------- TeamCity


@patch("tradecraft.adapters.cicd_exposure_probe.execute.requests.get")
def test_probe_teamcity_vulnerable(mock_get):
    mock_get.side_effect = [
        _resp(200, {"version": "2023.11.3"}),
        _resp(200, {"count": 2, "project": [
            {"id": "_Root", "name": "<Root project>"},
            {"id": "InternalTools", "name": "Internal Tools"},
        ]}),
    ]
    res = probe_teamcity("https://ci.example.com", timeout=5.0)
    assert res.is_teamcity is True
    assert res.teamcity_version == "2023.11.3"
    assert res.unauthenticated_access is True
    assert res.vulnerable is True
    assert res.status == "vulnerable"
    assert res.guest_projects_exposed == 2
    assert res.project_names == ["<Root project>", "Internal Tools"]


@patch("tradecraft.adapters.cicd_exposure_probe.execute.requests.get")
def test_probe_teamcity_guest_login_disabled(mock_get):
    mock_get.side_effect = [
        _resp(200, {"version": "2023.11.3"}),
        _resp(401),
    ]
    res = probe_teamcity("https://ci.example.com", timeout=5.0)
    assert res.connected is True
    assert res.vulnerable is False
    assert res.status == "auth_required"


@patch("tradecraft.adapters.cicd_exposure_probe.execute.requests.get")
def test_probe_teamcity_not_teamcity(mock_get):
    mock_get.return_value = _resp(200, {"other": "thing"})
    res = probe_teamcity("https://notteamcity.example.com", timeout=5.0)
    assert res.is_teamcity is False
    assert res.status == "not_teamcity"


# ---------------------------------------------------------------- execute() dispatcher


@patch("tradecraft.adapters.cicd_exposure_probe.execute.probe_teamcity")
@patch("tradecraft.adapters.cicd_exposure_probe.execute.probe_argocd")
def test_execute_auto_probes_both(mock_argocd, mock_teamcity):
    mock_argocd.return_value = ArgoCdResult(base_url="https://x", status="not_argocd")
    mock_teamcity.return_value = TeamCityResult(base_url="https://x", status="not_teamcity")

    out = execute("x.example.com", service="auto")
    mock_argocd.assert_called_once()
    mock_teamcity.assert_called_once()
    assert out.argocd is not None
    assert out.teamcity is not None
    assert out.vulnerable is False


@patch("tradecraft.adapters.cicd_exposure_probe.execute.probe_teamcity")
@patch("tradecraft.adapters.cicd_exposure_probe.execute.probe_argocd")
def test_execute_explicit_argocd_only(mock_argocd, mock_teamcity):
    mock_argocd.return_value = ArgoCdResult(base_url="https://x", vulnerable=True, status="vulnerable")

    out = execute("x.example.com", service="argocd")
    mock_argocd.assert_called_once()
    mock_teamcity.assert_not_called()
    assert out.teamcity is None
    assert out.vulnerable is True


def test_execute_invalid_target():
    out = execute("   ")
    assert out.error is not None
    assert out.vulnerable is False


# ---------------------------------------------------------------- parse()


def test_parse_includes_findings_for_vulnerable_services():
    res = CicdExposureResult(
        target="x.example.com",
        argocd=ArgoCdResult(base_url="https://x", vulnerable=True, status="vulnerable", applications_exposed=2),
        teamcity=TeamCityResult(base_url="https://x", vulnerable=False, status="auth_required"),
        vulnerable=True,
        summary="Argo CD VULNERABLE; TeamCity auth_required",
    )
    out = parse(res)
    assert out["argocd"]["applications_exposed"] == 2
    assert out["teamcity"]["vulnerable"] is False
    assert len(out["findings"]) == 1
    assert "Argo CD" in out["findings"][0]
