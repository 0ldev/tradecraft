"""
Unit tests for docker_api_probe adapter.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from tradecraft.adapters.docker_api_probe import execute as docker_execute


def _mock_get(url, **kwargs):
    resp = MagicMock()
    if url.endswith("/version"):
        resp.status_code = 200
        resp.json.return_value = {
            "Version": "24.0.5", "ApiVersion": "1.43", "Os": "linux",
            "Arch": "x86_64", "KernelVersion": "5.15.0",
        }
    elif url.endswith("/info"):
        resp.status_code = 200
        resp.json.return_value = {
            "Containers": 3, "ContainersRunning": 2, "Images": 10,
            "ServerVersion": "24.0.5", "OperatingSystem": "Ubuntu 22.04",
        }
    elif url.endswith("/containers/json"):
        resp.status_code = 200
        resp.json.return_value = [
            {"Names": ["/web-app"], "Image": "nginx"},
            {"Names": ["/db"], "Image": "postgres"},
        ]
    return resp


def test_full_success():
    with patch("tradecraft.adapters.docker_api_probe.execute.requests.get", side_effect=_mock_get):
        result = docker_execute.execute(target="192.168.1.50:2375")

    assert result.reachable is True
    assert result.version_info["Version"] == "24.0.5"
    assert result.info["Containers"] == 3
    assert len(result.containers) == 2
    assert result.error is None


def test_version_404_not_reachable():
    resp = MagicMock(status_code=404)
    with patch("tradecraft.adapters.docker_api_probe.execute.requests.get", return_value=resp):
        result = docker_execute.execute(target="192.168.1.50")

    assert result.reachable is False
    assert "HTTP 404" in result.error


def test_version_request_exception():
    import requests
    with patch(
        "tradecraft.adapters.docker_api_probe.execute.requests.get",
        side_effect=requests.RequestException("refused"),
    ):
        result = docker_execute.execute(target="192.168.1.50")

    assert result.reachable is False
    assert "GET /version failed" in result.error


def test_version_non_json_body():
    resp = MagicMock(status_code=200)
    resp.json.side_effect = ValueError("no json")
    with patch("tradecraft.adapters.docker_api_probe.execute.requests.get", return_value=resp):
        result = docker_execute.execute(target="192.168.1.50")

    assert result.reachable is False
    assert "non-JSON" in result.error


def test_partial_success_info_fails():
    import requests

    def side_effect(url, **kwargs):
        if url.endswith("/version"):
            resp = MagicMock(status_code=200)
            resp.json.return_value = {"Version": "24.0.5"}
            return resp
        raise requests.RequestException("info endpoint down")

    with patch("tradecraft.adapters.docker_api_probe.execute.requests.get", side_effect=side_effect):
        result = docker_execute.execute(target="192.168.1.50")

    assert result.reachable is True
    assert result.info == {}


def test_split_host_port():
    assert docker_execute.split_host_port("192.168.1.50") == ("192.168.1.50", 2375)
    assert docker_execute.split_host_port("192.168.1.50:2376") == ("192.168.1.50", 2376)
    assert docker_execute.split_host_port("http://192.168.1.50:2375") == ("192.168.1.50", 2375)
