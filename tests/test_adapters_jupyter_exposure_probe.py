"""Unit tests for the jupyter_exposure_probe adapter. Mocks requests.get."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from tradecraft.adapters.jupyter_exposure_probe.execute import (
    normalize_base_url,
    execute,
    split_host_port,
)
from tradecraft.adapters.jupyter_exposure_probe.parse import parse


def _resp(status_code, data=None, json_error=False):
    resp = MagicMock()
    resp.status_code = status_code
    if json_error:
        resp.json.side_effect = ValueError("not json")
    else:
        resp.json.return_value = data
    return resp


def test_split_host_port_variants():
    assert split_host_port("notebook.local") == ("notebook.local", 8888)
    assert split_host_port("notebook.local:8889") == ("notebook.local", 8889)
    assert split_host_port("https://notebook.local") == ("notebook.local", 8888)
    assert split_host_port("https://notebook.local:443") == ("notebook.local", 443)


def test_normalize_base_url_preserves_path_prefix():
    assert normalize_base_url("notebook.local") == ("http://notebook.local:8888", "notebook.local", 8888)
    assert normalize_base_url("https://example.com/jupyter") == (
        "https://example.com/jupyter",
        "example.com",
        443,
    )


def test_execute_detects_unauthenticated_jupyter():
    def fake_get(url, **kwargs):
        if url.endswith("/api"):
            return _resp(200, {"version": "6.5.4"})
        if url.endswith("/api/kernels"):
            return _resp(200, [])
        raise AssertionError(url)

    with patch("tradecraft.adapters.jupyter_exposure_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.get.side_effect = fake_get
        raw = execute(target="notebook.local")

    result = parse(raw)
    assert result["service"] == "jupyter"
    assert result["vulnerable"] is True
    assert result["status"] == "vulnerable"
    assert result["kernels_listed"] == 0
    assert result["version"] == "6.5.4"
    assert [e["path"] for e in result["endpoints"]] == ["/api", "/api/kernels"]


def test_execute_reports_auth_required_jupyter():
    with patch("tradecraft.adapters.jupyter_exposure_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.get.return_value = _resp(401, None, json_error=True)
        raw = execute(target="notebook.local")

    result = parse(raw)
    assert result["service"] == "jupyter"
    assert result["auth_required"] is True
    assert result["vulnerable"] is False
    assert result["status"] == "auth_required"


def test_execute_detects_jupyterhub_user_listing():
    def fake_get(url, **kwargs):
        if url.endswith("/hub/api/users"):
            return _resp(200, [{"name": "alice"}, {"name": "bob"}])
        if url.endswith("/hub/api"):
            return _resp(200, {"version": "4.0.1"})
        if url.endswith("/api"):
            return _resp(404, None, json_error=True)
        raise AssertionError(url)

    with patch("tradecraft.adapters.jupyter_exposure_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.get.side_effect = fake_get
        raw = execute(target="hub.example.com")

    result = parse(raw)
    assert result["service"] == "jupyterhub"
    assert result["vulnerable"] is True
    assert result["users_listed"] == 2


def test_execute_reports_not_jupyter():
    with patch("tradecraft.adapters.jupyter_exposure_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.get.return_value = _resp(404, None, json_error=True)
        raw = execute(target="www.example.com")

    result = parse(raw)
    assert result["vulnerable"] is False
    assert result["status"] == "not_jupyter"
    assert "neither /api nor /hub/api" in result["error"]


def test_execute_network_error_is_reported():
    with patch("tradecraft.adapters.jupyter_exposure_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.get.side_effect = Exception("connection refused")
        raw = execute(target="down.example.com")

    result = parse(raw)
    assert result["vulnerable"] is False
    assert "connection refused" in result["error"]
