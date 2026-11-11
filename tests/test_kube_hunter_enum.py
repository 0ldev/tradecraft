"""
Unit tests for the kube_hunter_enum adapter, parser, Tool wrapper, and
contract.

The success fixtures are real kube-hunter 0.6.8 JSON reports captured on
CT 115: the non-empty one from a passive scan of a local fake API server
on 127.0.0.1:6443, and the empty one from a scan of a non-Kubernetes lab
host. The plain "couldn't find any clusters" message is also a real
capture.
"""
from __future__ import annotations

import json
import subprocess
from types import SimpleNamespace

import pytest

from tradecraft.adapters.kube_hunter_enum import execute as kh_execute
from tradecraft.adapters.kube_hunter_enum import parse as kh_parse
from tradecraft.tools.kube_hunter_enum import KubeHunterEnum
from tradecraft.tools.profiles import load_profile

# Captured from a passive kube-hunter 0.6.8 scan against a local fake API
# server (reformatted only for readability; values are verbatim).
REAL_NONEMPTY_REPORT = {
    "nodes": [{"type": "Node/Master", "location": "127.0.0.1"}],
    "services": [{"service": "API Server", "location": "127.0.0.1:6443"}],
    "vulnerabilities": [
        {
            "location": "127.0.0.1:6443",
            "vid": "KHV006",
            "category": "Initial Access // Exposed sensitive interfaces",
            "severity": "high",
            "vulnerability": "Insecure (HTTP) access to API",
            "description": (
                "The API Server port is accessible over HTTP, and therefore "
                "unencrypted.\n    Depending on your RBAC settings this could "
                "expose access to or control of your cluster."
            ),
            "evidence": "b'{\"kind\": \"APIVersions\", \"versions\": [\"v1\"]}'",
            "avd_reference": "https://avd.aquasec.com/kube-hunter/khv006/",
            "hunter": "API Server Hunter",
        },
        {
            "location": "127.0.0.1:6443",
            "vid": "KHV002",
            "category": "Initial Access // Exposed sensitive interfaces",
            "severity": "high",
            "vulnerability": "K8s Version Disclosure",
            "description": (
                "The kubernetes version could be obtained from the "
                "/version endpoint"
            ),
            "evidence": "v1.27.0",
            "avd_reference": "https://avd.aquasec.com/kube-hunter/khv002/",
            "hunter": "Api Version Hunter",
        },
    ],
}

NONEMPTY_JSON = json.dumps(REAL_NONEMPTY_REPORT)

# Captured from `kube-hunter --remote 192.168.15.23 ... --report json`.
EMPTY_JSON = json.dumps(
    {"nodes": [], "services": [], "vulnerabilities": []}
)

# Captured from `kube-hunter --remote 127.0.0.1 --report bogus ...`.
REAL_NO_CLUSTERS_STDOUT = "\nKube Hunter couldn't find any clusters\n"


def test_parse_real_nonempty_report():
    parsed = kh_parse.parse_kube_hunter_report(NONEMPTY_JSON)

    assert parsed["status"] == "success"
    assert parsed["mode"] == "passive"
    assert parsed["node_count"] == 1
    assert parsed["service_count"] == 1
    assert parsed["vulnerability_count"] == 2
    assert parsed["severity_counts"] == {
        "critical": 0,
        "high": 2,
        "medium": 0,
        "low": 0,
        "unknown": 0,
    }
    assert parsed["nodes_truncated"] is False
    assert parsed["services_truncated"] is False
    assert parsed["vulnerabilities_truncated"] is False

    assert parsed["nodes"][0]["type"] == "Node/Master"
    assert parsed["services"][0]["service"] == "API Server"
    assert parsed["vulnerabilities"][0]["vid"] == "KHV006"
    assert parsed["vulnerabilities"][0]["severity"] == "high"
    assert parsed["vulnerabilities"][1]["vid"] == "KHV002"


def test_parse_real_empty_report():
    parsed = kh_parse.parse_kube_hunter_report(EMPTY_JSON)

    assert parsed["status"] == "success"
    assert parsed["node_count"] == 0
    assert parsed["service_count"] == 0
    assert parsed["vulnerability_count"] == 0
    assert parsed["severity_counts"]["high"] == 0
    assert parsed["nodes"] == []
    assert parsed["services"] == []
    assert parsed["vulnerabilities"] == []
    assert "notes" in parsed
    assert "found no Kubernetes nodes or services" in parsed["notes"][0]


def test_parse_malformed_json_is_failed():
    parsed = kh_parse.parse_kube_hunter_report("{not json")
    assert parsed["status"] == "failed"
    assert "could not parse kube-hunter JSON report" in parsed["error"]


def test_parse_top_level_not_object_is_failed():
    parsed = kh_parse.parse_kube_hunter_report("[]")
    assert parsed["status"] == "failed"
    assert "expected an object" in parsed["error"]


def test_parse_non_list_section_is_failed():
    parsed = kh_parse.parse_kube_hunter_report(
        json.dumps({"nodes": {}, "services": [], "vulnerabilities": []})
    )
    assert parsed["status"] == "failed"
    assert "must be lists" in parsed["error"]


def test_parse_unknown_severity_counts():
    data = {
        "nodes": [],
        "services": [],
        "vulnerabilities": [
            {"location": "10.0.0.5:6443", "severity": "weird"},
        ],
    }
    parsed = kh_parse.parse_kube_hunter_report(json.dumps(data))
    assert parsed["severity_counts"]["unknown"] == 1


def test_parse_caps_entries_but_keeps_counts():
    data = {
        "nodes": [
            {"type": "Node/Master", "location": f"10.0.0.{index}"}
            for index in range(60)
        ],
        "services": [
            {"service": "API Server", "location": f"10.0.0.1:{6443 + index}"}
            for index in range(120)
        ],
        "vulnerabilities": [
            {
                "location": "10.0.0.1:6443",
                "severity": "high",
                "vid": f"KHV{index}",
            }
            for index in range(250)
        ],
    }
    parsed = kh_parse.parse_kube_hunter_report(json.dumps(data))

    assert parsed["node_count"] == 60
    assert parsed["service_count"] == 120
    assert parsed["vulnerability_count"] == 250
    assert len(parsed["nodes"]) == kh_parse.MAX_NODES_RETURNED
    assert len(parsed["services"]) == kh_parse.MAX_SERVICES_RETURNED
    assert (
        len(parsed["vulnerabilities"])
        == kh_parse.MAX_VULNERABILITIES_RETURNED
    )
    assert parsed["nodes_truncated"] is True
    assert parsed["services_truncated"] is True
    assert parsed["vulnerabilities_truncated"] is True
    assert parsed["severity_counts"]["high"] == 250


@pytest.mark.parametrize(
    "target,kind,value",
    [
        ("10.0.0.5", "host", "10.0.0.5"),
        ("dc01.corp.local", "host", "dc01.corp.local"),
        ("10.0.0.5:6443", "host", "10.0.0.5"),
        ("https://10.0.0.5:6443", "host", "10.0.0.5"),
        ("10.0.0.0/24", "cidr", "10.0.0.0/24"),
        ("10.0.0.5/24", "cidr", "10.0.0.0/24"),
    ],
)
def test_parse_target_accepts(target, kind, value):
    parsed_kind, parsed_value, error = kh_parse.parse_target(target)
    assert error is None
    assert parsed_kind == kind
    assert parsed_value == value


def test_parse_target_rejects_broad_cidr():
    _, _, error = kh_parse.parse_target("10.0.0.0/16")
    assert "broader than /24" in error


def test_parse_target_rejects_target_list():
    _, _, error = kh_parse.parse_target("10.0.0.1,10.0.0.2")
    assert "target lists are not accepted" in error


def test_parse_target_rejects_ip_range():
    _, _, error = kh_parse.parse_target("10.0.0.1-10.0.0.5")
    assert "IP ranges are not accepted" in error


def test_parse_target_rejects_local_file(tmp_path):
    target_file = tmp_path / "targets.txt"
    target_file.write_text("10.0.0.1\n")
    _, _, error = kh_parse.parse_target(str(target_file))
    assert "local file" in error


def test_parse_target_rejects_empty():
    _, _, error = kh_parse.parse_target("  ")
    assert "empty target host" in error


def test_parse_target_rejects_invalid_cidr():
    _, _, error = kh_parse.parse_target("not-a-cidr/24")
    assert "invalid CIDR" in error


@pytest.mark.parametrize(
    "location,host,port",
    [
        ("127.0.0.1:6443", "127.0.0.1", 6443),
        ("127.0.0.1", "127.0.0.1", None),
        ("127.0.0.1:6443/api", "127.0.0.1", 6443),
        ("[::1]:6443", "::1", 6443),
        ("", "", None),
    ],
)
def test_parse_host_port(location, host, port):
    assert kh_parse.parse_host_port(location) == (host, port)


def test_build_argv_host_exact():
    argv = kh_execute.build_argv(target="10.0.0.5")
    assert argv == [
        "kube-hunter",
        "--remote",
        "10.0.0.5",
        "--report",
        "json",
        "--dispatch",
        "stdout",
        "--log",
        "none",
        "--network-timeout",
        "3",
        "--num-worker-threads",
        "32",
    ]
    assert "--active" not in argv


def test_build_argv_cidr_token_and_cve():
    argv = kh_execute.build_argv(
        target="10.0.0.0/24",
        token="JWT",
        cve_hunting=True,
    )
    assert argv[:4] == ["kube-hunter", "--cidr", "10.0.0.0/24", "--report"]
    assert argv[argv.index("--service-account-token") + 1] == "JWT"
    assert "--enable-cve-hunting" in argv
    assert "--active" not in argv


def test_build_argv_raises_on_invalid_target():
    with pytest.raises(ValueError, match="broader than /24"):
        kh_execute.build_argv(target="10.0.0.0/16")


def test_execute_rejects_broad_cidr():
    res = kh_execute.execute(target="10.0.0.0/16")
    assert "broader than /24" in res.error


def test_execute_missing_binary(monkeypatch):
    monkeypatch.setattr(
        kh_execute, "find_kube_hunter_binary", lambda: None
    )
    res = kh_execute.execute(target="10.0.0.5")
    assert "not found on path" in res.error.lower()


def test_execute_timeout(monkeypatch):
    monkeypatch.setattr(
        kh_execute,
        "find_kube_hunter_binary",
        lambda: "/usr/local/bin/kube-hunter",
    )

    def fake_runner(argv, **kwargs):
        raise subprocess.TimeoutExpired(cmd=argv, timeout=5)

    res = kh_execute.execute(target="10.0.0.5", runner=fake_runner)
    assert "timed out" in res.error.lower()


def test_execute_success_with_fake_runner(monkeypatch):
    monkeypatch.setattr(
        kh_execute,
        "find_kube_hunter_binary",
        lambda: "/usr/local/bin/kube-hunter",
    )
    captured = {}

    def fake_runner(argv, **kwargs):
        captured["argv"] = argv
        return SimpleNamespace(
            stdout=EMPTY_JSON, stderr="", returncode=0
        )

    res = kh_execute.execute(target="10.0.0.5", runner=fake_runner)

    assert res.error is None
    assert res.target == "10.0.0.5"
    assert res.target_kind == "host"
    assert res.stdout == EMPTY_JSON
    assert captured["argv"][0] == "/usr/local/bin/kube-hunter"
    assert "--active" not in captured["argv"]


def test_parse_result_plain_no_clusters_is_no_response():
    raw = kh_parse.RawKubeHunterResult(
        target="127.0.0.1",
        target_kind="host",
        stdout=REAL_NO_CLUSTERS_STDOUT,
        stderr="",
        returncode=0,
    )
    parsed = kh_parse.parse_kube_hunter_enum_result(raw)

    assert parsed["status"] == "no_response"
    assert "could not find any clusters" in parsed["notes"][0]
    assert parsed["mode"] == "passive"


def test_parse_result_empty_stdout_is_failed():
    raw = kh_parse.RawKubeHunterResult(
        target="10.0.0.5",
        target_kind="host",
        stdout="",
        stderr="Traceback (most recent call last):\nRuntimeError: boom",
        returncode=1,
    )
    parsed = kh_parse.parse_kube_hunter_enum_result(raw)

    assert parsed["status"] == "failed"
    assert parsed["error"] == "RuntimeError: boom"


def test_parse_result_success_carries_target():
    raw = kh_parse.RawKubeHunterResult(
        target="10.0.0.5",
        target_kind="host",
        stdout=NONEMPTY_JSON,
        stderr="",
        returncode=0,
    )
    parsed = kh_parse.parse_kube_hunter_enum_result(raw)
    assert parsed["status"] == "success"
    assert parsed["target"] == "10.0.0.5"
    assert parsed["target_kind"] == "host"
    assert parsed["service_count"] == 1


def test_tool_wrapper_evidence_and_facts(monkeypatch):
    tool = KubeHunterEnum()
    assert tool.tool_id == "kube_hunter_enum"
    assert tool.destructive is False

    monkeypatch.setattr(
        kh_execute,
        "find_kube_hunter_binary",
        lambda: "/usr/local/bin/kube-hunter",
    )

    def fake_run(argv, **kwargs):
        return SimpleNamespace(
            stdout=NONEMPTY_JSON, stderr="", returncode=0
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = tool.run(target="127.0.0.1")
    assert result["status"] == "success"
    assert result["node_count"] == 1
    assert result["service_count"] == 1
    assert result["vulnerability_count"] == 2
    assert result["severity_counts"]["high"] == 2
    assert "_full_evidence" in result

    evidence = tool.extract_evidence({"target": "127.0.0.1"}, result)
    assert evidence is not None
    ev_target, ev_data = evidence
    assert ev_target == "127.0.0.1"
    assert ev_data["mode"] == "passive"
    assert ev_data["report"] == NONEMPTY_JSON
    assert json.loads(ev_data["report"])["services"][0]["service"] == (
        "API Server"
    )

    result["evidence_id"] = "kube_hunter_enum:127.0.0.1"
    facts = tool.extract_facts({"target": "127.0.0.1"}, result)
    assert len(facts) == 1
    fact = facts[0]
    assert fact["host"] == "127.0.0.1"
    assert fact["port"] == 6443
    assert fact["protocol"] == "k8s"
    assert fact["k8s_service"] == "API Server"
    assert fact["k8s_vulnerable"] is True
    assert fact["k8s_vulnerability_count"] == 2
    assert fact["k8s_high_count"] == 2
    assert fact["k8s_critical_count"] == 0
    assert fact["evidence"] == "kube_hunter_enum:127.0.0.1"


def test_tool_no_response_has_no_facts(monkeypatch):
    tool = KubeHunterEnum()
    monkeypatch.setattr(
        kh_execute,
        "find_kube_hunter_binary",
        lambda: "/usr/local/bin/kube-hunter",
    )

    def fake_run(argv, **kwargs):
        return SimpleNamespace(
            stdout=REAL_NO_CLUSTERS_STDOUT, stderr="", returncode=0
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = tool.run(target="127.0.0.1")
    assert result["status"] == "no_response"
    assert tool.extract_facts({"target": "127.0.0.1"}, result) == []
    # The transcript is still useful evidence of what ran.
    assert tool.extract_evidence({"target": "127.0.0.1"}, result) is not None


def test_tool_vulnerability_without_service_still_gets_fact(monkeypatch):
    tool = KubeHunterEnum()
    monkeypatch.setattr(
        kh_execute,
        "find_kube_hunter_binary",
        lambda: "/usr/local/bin/kube-hunter",
    )
    report = json.dumps(
        {
            "nodes": [],
            "services": [],
            "vulnerabilities": [
                {
                    "location": "10.0.0.5:10250",
                    "severity": "medium",
                    "vid": "KHV999",
                    "vulnerability": "test finding",
                }
            ],
        }
    )

    def fake_run(argv, **kwargs):
        return SimpleNamespace(stdout=report, stderr="", returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = tool.run(target="10.0.0.5")
    result["evidence_id"] = "kube_hunter_enum:10.0.0.5"
    facts = tool.extract_facts({"target": "10.0.0.5"}, result)

    assert len(facts) == 1
    assert facts[0]["host"] == "10.0.0.5"
    assert facts[0]["port"] == 10250
    assert facts[0]["k8s_service"] == "unknown"
    assert facts[0]["k8s_vulnerable"] is True
    assert facts[0]["k8s_medium_count"] == 1


def test_tool_cidr_evidence_key(monkeypatch):
    tool = KubeHunterEnum()
    monkeypatch.setattr(
        kh_execute,
        "find_kube_hunter_binary",
        lambda: "/usr/local/bin/kube-hunter",
    )

    def fake_run(argv, **kwargs):
        return SimpleNamespace(stdout=EMPTY_JSON, stderr="", returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = tool.run(target="10.0.0.0/24")
    evidence = tool.extract_evidence({"target": "10.0.0.0/24"}, result)
    assert evidence is not None
    assert evidence[0] == "10.0.0.0/24"


def test_tool_is_available(monkeypatch):
    tool = KubeHunterEnum()
    monkeypatch.setattr(
        kh_execute,
        "find_kube_hunter_binary",
        lambda: "/usr/local/bin/kube-hunter",
    )
    assert tool.is_available() is True

    monkeypatch.setattr(kh_execute, "find_kube_hunter_binary", lambda: None)
    assert tool.is_available() is False


def test_kube_hunter_enum_profile_membership():
    assert "kube_hunter_enum" in load_profile("kubernetes")
