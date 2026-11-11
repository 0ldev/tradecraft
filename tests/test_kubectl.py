"""
Unit tests for kubectl adapter and tool layer.
"""
from __future__ import annotations

import base64
import json
from unittest.mock import MagicMock, patch

import pytest

from tradecraft.adapters.kubectl import execute as k8s_execute
from tradecraft.adapters.kubectl import parse as k8s_parse
from tradecraft.tools.kubectl import Kubectl
from tradecraft.tools.profiles import load_profile


def test_parse_target_endpoint():
    assert k8s_parse.parse_target_endpoint("https://10.0.0.1:6443") == "10.0.0.1:6443"
    assert k8s_parse.parse_target_endpoint("http://k8s.local:6443/") == "k8s.local:6443"
    assert k8s_parse.parse_target_endpoint("192.168.1.5:6443") == "192.168.1.5:6443"


def test_parse_host_port():
    assert k8s_parse.parse_host_port("10.0.0.1:6443") == ("10.0.0.1", 6443)
    assert k8s_parse.parse_host_port("k8s.cluster") == ("k8s.cluster", 6443)


def test_namespace_from_token():
    # Valid JWT with namespace claim
    claims = {"kubernetes.io/serviceaccount/namespace": "kube-system", "sub": "system:serviceaccount:kube-system:admin"}
    payload_b64 = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    dummy_jwt = f"header.{payload_b64}.signature"
    assert k8s_parse.namespace_from_token(dummy_jwt) == "kube-system"

    # Non-JWT / opaque string
    assert k8s_parse.namespace_from_token("opaque_token_string") is None
    assert k8s_parse.namespace_from_token("") is None


def test_build_argv():
    argv1 = k8s_execute.build_can_i_argv("10.0.0.1:6443", "token123", namespace="kube-system")
    assert "--server=https://10.0.0.1:6443" in argv1
    assert "--token=token123" in argv1
    assert "-n" in argv1
    assert "kube-system" in argv1
    assert "auth" in argv1
    assert "can-i" in argv1

    argv2 = k8s_execute.build_get_secrets_argv("10.0.0.1:6443", "token123", namespace=None)
    assert "--all-namespaces" in argv2


def test_parse_can_i_output_overprivileged():
    can_i_json = json.dumps(
        {
            "status": {
                "resourceRules": [
                    {"verbs": ["*"], "resources": ["*"], "apiGroups": ["*"]}
                ]
            }
        }
    )
    overprivileged, can_get_secrets, rules = k8s_parse.parse_can_i_output(can_i_json)
    assert overprivileged is True
    assert can_get_secrets is True
    assert len(rules) == 1


def test_parse_can_i_output_restricted():
    can_i_json = json.dumps(
        {
            "status": {
                "resourceRules": [
                    {"verbs": ["get", "list"], "resources": ["pods", "configmaps"], "apiGroups": [""]}
                ]
            }
        }
    )
    overprivileged, can_get_secrets, rules = k8s_parse.parse_can_i_output(can_i_json)
    assert overprivileged is False
    assert can_get_secrets is False
    assert len(rules) == 1


def test_parse_can_i_output_tabular():
    tabular_output = """Resources                                       Non-Resource URLs   Resource Names   Verbs
*.*                                             []                  []               [*]
selfsubjectaccessreviews.authorization.k8s.io   []                  []               [create]
secrets                                         []                  []               [get list watch]
pods                                            []                  []               [get]
"""
    overprivileged, can_get_secrets, rules = k8s_parse.parse_can_i_output(tabular_output)
    assert overprivileged is True
    assert can_get_secrets is True
    assert len(rules) == 4
    assert rules[2]["resources"] == ["secrets"]
    assert rules[2]["verbs"] == ["get", "list", "watch"]


def test_parse_secrets_output():
    secret_val = base64.b64encode(b"super_secret_db_password").decode()
    secrets_json = json.dumps(
        {
            "items": [
                {
                    "metadata": {"name": "db-creds", "namespace": "prod"},
                    "data": {"password": secret_val},
                }
            ]
        }
    )
    secrets = k8s_parse.parse_secrets_output(secrets_json)
    assert len(secrets) == 1
    assert secrets[0]["name"] == "db-creds"
    assert secrets[0]["namespace"] == "prod"
    assert secrets[0]["key"] == "password"
    assert secrets[0]["value"] == "super_secret_db_password"


def test_execute_with_mock_runner():
    mock_runner = MagicMock()

    can_i_proc = MagicMock()
    can_i_proc.returncode = 0
    can_i_proc.stdout = json.dumps(
        {
            "status": {
                "resourceRules": [
                    {"verbs": ["get", "list"], "resources": ["secrets"], "apiGroups": [""]}
                ]
            }
        }
    )

    secrets_proc = MagicMock()
    secrets_proc.returncode = 0
    secrets_proc.stdout = json.dumps(
        {
            "items": [
                {
                    "metadata": {"name": "api-key", "namespace": "default"},
                    "data": {"key": base64.b64encode(b"12345").decode()},
                }
            ]
        }
    )

    mock_runner.side_effect = [can_i_proc, secrets_proc]

    with patch("tradecraft.adapters.kubectl.execute.find_kubectl_binary", return_value="/usr/local/bin/kubectl"):
        res = k8s_execute.execute(
            target="10.0.0.1:6443",
            token="bearer_token",
            runner=mock_runner,
        )

    assert res.error is None
    assert len(res.permissions) == 1
    assert len(res.secrets) == 1
    assert res.secrets[0]["value"] == "12345"


def test_execute_missing_token():
    res = k8s_execute.execute("10.0.0.1:6443", token="")
    assert res.error == "missing required token parameter"


def test_tool_run_and_facts():
    tool = Kubectl()
    assert tool.tool_id == "kubectl"
    assert tool.destructive is False

    with patch("tradecraft.adapters.kubectl.execute.execute") as mock_exec:
        mock_raw = k8s_parse.RawKubectlResult(
            target="10.0.0.1:6443",
            namespace="kube-system",
            overprivileged=True,
            permissions=[{"verbs": ["*"], "resources": ["*"]}],
            secrets=[{"namespace": "kube-system", "name": "token", "key": "token", "value": "val"}],
        )
        mock_exec.return_value = mock_raw

        result = tool.run(target="10.0.0.1:6443", token="token123")
        assert result["overprivileged"] is True
        assert result["permissions_count"] == 1
        assert result["secrets_count"] == 1

        evidence = tool.extract_evidence({"target": "10.0.0.1:6443"}, result)
        assert evidence is not None
        host, full = evidence
        assert host == "10.0.0.1"
        assert full["overprivileged"] is True

        facts = tool.extract_facts({"target": "10.0.0.1:6443"}, result)
        assert len(facts) == 1
        assert facts[0]["host"] == "10.0.0.1"
        assert facts[0]["port"] == 6443
        assert facts[0]["k8s_api_server"] is True
        assert facts[0]["k8s_overprivileged"] is True


def test_profile_assignment():
    k8s_tools = load_profile("kubernetes")
    web_tools = load_profile("web")

    assert "kubectl" in k8s_tools
    assert "kubectl" not in web_tools
