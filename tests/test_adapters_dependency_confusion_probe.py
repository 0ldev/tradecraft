"""Unit tests for dependency_confusion_probe adapter. Mocks requests.get."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from tradecraft.adapters.dependency_confusion_probe.execute import execute, parse_packages_param
from tradecraft.adapters.dependency_confusion_probe.parse import parse


def test_parse_packages_param_defaults_to_npm_and_caps_at_twenty():
    pairs = parse_packages_param("acme-utils,acme-pkg:pypi," + ",".join(f"pkg{i}" for i in range(25)))
    assert pairs[0] == ("acme-utils", "npm")
    assert pairs[1] == ("acme-pkg", "pypi")
    assert len(pairs) == 20


def _mock_response(status_code=404, text=""):
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    return resp


def test_execute_npm_unclaimed_404():
    with patch("tradecraft.adapters.dependency_confusion_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.get.return_value = _mock_response(status_code=404)
        result = execute(packages="acme-internal-utils:npm")
    assert result.error is None
    assert result.checks[0].status_code == 404


def test_execute_maven_queries_search_api():
    with patch("tradecraft.adapters.dependency_confusion_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.get.return_value = _mock_response(status_code=200, text='{"response":{"numFound":0}}')
        result = execute(packages="com.acme:internal-lib:maven")
    assert result.checks[0].ecosystem == "maven"
    assert "numFound" in result.checks[0].body


def test_parse_flags_squattable_npm_and_claimed_pypi():
    with patch("tradecraft.adapters.dependency_confusion_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception

        def fake_get(url, **kwargs):
            if "registry.npmjs.org" in url:
                return _mock_response(status_code=404)
            if "pypi.org" in url:
                return _mock_response(status_code=200)
            return _mock_response(status_code=200, text='{"response":{"numFound":1}}')

        mock_requests.get.side_effect = fake_get
        raw = execute(packages="acme-internal-utils:npm,requests:pypi,com.acme:lib:maven")
    result = parse(raw)
    assert result["squattable_count"] == 1
    assert "acme-internal-utils (npm)" in result["squattable_packages"]
    classifications = {r["name"]: r["classification"] for r in result["results"]}
    assert classifications["acme-internal-utils"] == "squattable"
    assert classifications["requests"] == "already_claimed"


def test_execute_no_valid_packages_errors():
    result = execute(packages="   ,  ")
    assert result.error is not None
