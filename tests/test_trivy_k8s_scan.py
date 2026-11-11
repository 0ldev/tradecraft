"""
Unit tests for the trivy_k8s_scan adapter, parser, Tool wrapper, and contract.

No `trivy` binary was available when these were written, so the report
fixture follows the field names in Trivy's documented `k8s` JSON output
(top-level ClusterName / Vulnerabilities / Misconfigurations, each a list of
per-resource objects with Namespace / Kind / Name / Results). Re-capture
against a real cluster and update REPORT_FIXTURE if the layout differs.
subprocess.run is mocked everywhere: no test reaches a cluster.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from unittest.mock import patch

import yaml

from tradecraft.adapters.trivy_k8s_scan import execute as k8s_execute
from tradecraft.adapters.trivy_k8s_scan import parse as k8s_parse
from tradecraft.adapters.trivy_k8s_scan.parse import RawTrivyK8sResult
from tradecraft.tools.profiles import load_profile
from tradecraft.tools.spec_loader import load_destructive_flag, load_required_binary, load_spec
from tradecraft.tools.trivy_k8s_scan import TrivyK8sScan


def _cve(vid, pkg, installed, fixed, severity, title):
    return {
        "VulnerabilityID": vid,
        "PkgName": pkg,
        "InstalledVersion": installed,
        "FixedVersion": fixed,
        "Severity": severity,
        "Title": title,
        "PrimaryURL": f"https://avd.aquasec.com/nvd/{vid.lower()}",
    }


def _check(check_id, severity, title, message, status="FAIL"):
    return {
        "Type": "kubernetes",
        "ID": check_id,
        "AVDID": check_id,
        "Title": title,
        "Message": message,
        "Severity": severity,
        "Status": status,
        "PrimaryURL": f"https://avd.aquasec.com/misconfig/{check_id.lower()}",
    }


REPORT_FIXTURE = {
    "ClusterName": "kind-tradecraft-lab",
    "Vulnerabilities": [
        {
            "Namespace": "payments",
            "Kind": "Deployment",
            "Name": "checkout",
            "Results": [
                {
                    "Target": "Deployment/checkout",
                    "Class": "os-pkgs",
                    "Type": "alpine",
                    "Vulnerabilities": [
                        _cve("CVE-2026-40200", "musl", "1.2.4_git20230717-r5",
                             "1.2.4_git20230717-r6", "HIGH", "musl qsort memory corruption"),
                        _cve("CVE-2024-58251", "busybox", "1.36.1-r20",
                             "1.36.1-r21", "MEDIUM", "netstat local privilege issue"),
                    ],
                },
            ],
        },
        {
            "Namespace": "kube-system",
            "Kind": "Deployment",
            "Name": "legacy-proxy",
            "Results": [
                {
                    "Target": "Deployment/legacy-proxy",
                    "Class": "os-pkgs",
                    "Type": "debian",
                    "Vulnerabilities": [
                        _cve("CVE-2025-0001", "openssl", "3.0.11-1", "3.0.13-1",
                             "CRITICAL", "openssl remote code execution"),
                    ],
                },
            ],
        },
    ],
    "Misconfigurations": [
        {
            "Namespace": "payments",
            "Kind": "Pod",
            "Name": "checkout-7d9f-abcde",
            "Results": [
                {
                    "Target": "Pod/checkout-7d9f-abcde",
                    "Class": "config",
                    "Type": "kubernetes",
                    "MisconfSummary": {"Successes": 20, "Failures": 2},
                    "Misconfigurations": [
                        _check("KSV017", "HIGH", "Privileged container",
                               "Container 'app' should set 'securityContext.privileged' to false"),
                        _check("KSV001", "MEDIUM", "Process can elevate its own privileges",
                               "Container 'app' should set allowPrivilegeEscalation to false"),
                        _check("KSV014", "LOW", "Root file system is not read-only",
                               "Container should set readOnlyRootFilesystem", status="PASS"),
                    ],
                },
            ],
        },
        {
            "Namespace": "default",
            "Kind": "ClusterRoleBinding",
            "Name": "dev-admin",
            "Results": [
                {
                    "Target": "ClusterRoleBinding/dev-admin",
                    "Class": "config",
                    "Type": "kubernetes",
                    "Misconfigurations": [
                        _check("KSV111", "CRITICAL", "Binding grants cluster-admin",
                               "ClusterRoleBinding binds cluster-admin to a non-system subject"),
                    ],
                },
            ],
        },
    ],
}


def _completed(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def _fake_run_writing(report_text, captured, returncode=0, stderr="", stdout=""):
    """Fake subprocess.run that writes report_text to the --output path, the
    way the real binary does, and records argv/kwargs."""
    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        out_path = argv[argv.index("--output") + 1]
        if report_text is not None:
            with open(out_path, "w") as handle:
                handle.write(report_text)
        return _completed(returncode=returncode, stdout=stdout, stderr=stderr)
    return fake_run


def _kubeconfig(tmp_path):
    path = tmp_path / "kubeconfig"
    path.write_text("apiVersion: v1\nkind: Config\n")
    return str(path)


# ---------------------------------------------------------------------------
# Contract and profile placement
# ---------------------------------------------------------------------------

def test_contract_declares_kubeconfig_and_is_not_destructive():
    spec = load_spec("trivy_k8s_scan")
    assert spec.name == "trivy_k8s_scan"
    assert load_required_binary("trivy_k8s_scan") == "trivy"
    assert load_destructive_flag("trivy_k8s_scan") is False


def test_kubeconfig_is_required_and_namespace_context_are_optional():
    contract = yaml.safe_load(
        (Path(__file__).resolve().parents[1] / "config" / "tools" / "trivy_k8s_scan.yaml").read_text()
    )
    params = contract["parameters"]
    assert params["required"] == ["kubeconfig"]
    assert set(params["properties"]) == {"kubeconfig", "namespace", "context"}
    for name in ("kubeconfig", "namespace", "context"):
        assert params["properties"][name]["description"].strip()


def test_trivy_k8s_scan_in_kubernetes_profile_only():
    assert "trivy_k8s_scan" in load_profile("kubernetes")
    assert "trivy_k8s_scan" not in load_profile("web")
    assert "trivy_k8s_scan" not in load_profile("cloud")


# ---------------------------------------------------------------------------
# Adapter: input validation (no subprocess reached)
# ---------------------------------------------------------------------------

def test_missing_kubeconfig_file_is_rejected_without_running_trivy(tmp_path):
    with patch.object(k8s_execute.subprocess, "run") as run:
        raw = k8s_execute.execute(str(tmp_path / "nope"))
    run.assert_not_called()
    assert raw.error and "not found" in raw.error


def test_flag_like_kubeconfig_is_rejected(tmp_path):
    with patch.object(k8s_execute.subprocess, "run") as run:
        raw = k8s_execute.execute("--kubeconfig=/etc/shadow")
    run.assert_not_called()
    assert raw.error


def test_invalid_namespace_is_rejected(tmp_path):
    kc = _kubeconfig(tmp_path)
    for bad in ("Payments", "a b", "--all", "x" * 64):
        with patch.object(k8s_execute.subprocess, "run") as run:
            raw = k8s_execute.execute(kc, namespace=bad)
        run.assert_not_called()
        assert raw.error, bad


def test_flag_like_context_is_rejected(tmp_path):
    kc = _kubeconfig(tmp_path)
    with patch.object(k8s_execute.subprocess, "run") as run:
        raw = k8s_execute.execute(kc, context="--insecure-skip-tls-verify")
    run.assert_not_called()
    assert raw.error


# ---------------------------------------------------------------------------
# Adapter: argv construction and execution
# ---------------------------------------------------------------------------

def test_cluster_wide_argv_has_no_namespace_or_context(tmp_path):
    kc = _kubeconfig(tmp_path)
    captured = {}
    with patch.object(k8s_execute.subprocess, "run",
                      side_effect=_fake_run_writing(json.dumps(REPORT_FIXTURE), captured)):
        raw = k8s_execute.execute(kc)
    assert raw.error is None
    argv = captured["argv"]
    assert argv[:2] == ["trivy", "k8s"]
    assert argv[argv.index("--kubeconfig") + 1] == kc
    assert argv[argv.index("--report") + 1] == "all"
    assert argv[argv.index("--format") + 1] == "json"
    assert "--include-namespaces" not in argv
    assert argv[-1] == k8s_execute.TRIVY_INTERNAL_TIMEOUT  # no positional context
    assert "--fix" not in argv
    assert "--disable-node-collector" in argv  # node collector would deploy a Job/namespace
    assert captured["kwargs"]["timeout"] == k8s_execute.TIMEOUT_SECONDS
    assert captured["kwargs"]["stdin"] is subprocess.DEVNULL


def test_namespace_and_context_are_passed_as_scope_and_positional(tmp_path):
    kc = _kubeconfig(tmp_path)
    captured = {}
    with patch.object(k8s_execute.subprocess, "run",
                      side_effect=_fake_run_writing(json.dumps(REPORT_FIXTURE), captured)):
        k8s_execute.execute(kc, namespace="payments", context="prod-admin")
    argv = captured["argv"]
    assert argv[argv.index("--include-namespaces") + 1] == "payments"
    assert argv[-1] == "prod-admin"


def test_missing_binary_returns_error_not_exception(tmp_path):
    kc = _kubeconfig(tmp_path)
    with patch.object(k8s_execute.subprocess, "run", side_effect=FileNotFoundError):
        raw = k8s_execute.execute(kc)
    assert raw.error == "trivy executable not found on PATH"


def test_timeout_returns_error_not_exception(tmp_path):
    kc = _kubeconfig(tmp_path)
    with patch.object(k8s_execute.subprocess, "run",
                      side_effect=subprocess.TimeoutExpired(cmd="trivy", timeout=600)):
        raw = k8s_execute.execute(kc)
    assert raw.error and "timed out" in raw.error


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def _raw(report_text=None, returncode=0, error=None, stderr=""):
    return RawTrivyK8sResult(
        kubeconfig="/x/kubeconfig", namespace="", context="",
        returncode=returncode, error=error, stderr=stderr,
        report_text=json.dumps(REPORT_FIXTURE) if report_text is None else report_text,
    )


def test_misconfigurations_drop_passing_checks_and_sort_by_severity():
    out = k8s_parse.parse_trivy_k8s_result(_raw())
    assert out["status"] == "success"
    assert out["cluster"] == "kind-tradecraft-lab"
    ids = [m["check_id"] for m in out["misconfigurations"]]
    assert "KSV014" not in ids  # PASS status, excluded
    assert ids == ["KSV111", "KSV017", "KSV001"]  # CRITICAL, HIGH, MEDIUM
    first = out["misconfigurations"][0]
    assert first == {
        "resource_kind": "ClusterRoleBinding",
        "resource_name": "dev-admin",
        "namespace": "default",
        "check_id": "KSV111",
        "severity": "CRITICAL",
        "title": "Binding grants cluster-admin",
        "message": "ClusterRoleBinding binds cluster-admin to a non-system subject",
        "url": "https://avd.aquasec.com/misconfig/ksv111",
    }
    assert out["total_misconfigurations"] == 3
    assert out["misconfiguration_severity_counts"]["CRITICAL"] == 1
    assert out["misconfigurations_truncated"] is False


def test_cves_sorted_by_severity_with_resource_and_image_target():
    out = k8s_parse.parse_trivy_k8s_result(_raw())
    cves = out["vulnerabilities"]
    assert [c["vulnerability_id"] for c in cves] == ["CVE-2025-0001", "CVE-2026-40200", "CVE-2024-58251"]
    assert cves[0]["namespace"] == "kube-system"
    assert cves[0]["resource_name"] == "legacy-proxy"
    assert cves[0]["image_target"] == "Deployment/legacy-proxy"
    assert cves[1]["package"] == "musl"
    assert out["total_vulnerabilities"] == 3
    assert out["vulnerability_severity_counts"] == {
        "CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 0, "UNKNOWN": 0,
    }
    assert out["vulnerabilities_truncated"] is False


def test_both_lists_capped_at_100_with_truncation_flags():
    many_cves = [
        _cve(f"CVE-2026-{i:05d}", f"pkg{i}", "1", "2", "LOW", "t") for i in range(150)
    ]
    many_checks = [
        _check(f"KSV{i:03d}", "HIGH", "t", "m") for i in range(120)
    ]
    report = {
        "ClusterName": "big",
        "Vulnerabilities": [{"Namespace": "a", "Kind": "Pod", "Name": "p",
                             "Results": [{"Target": "t", "Vulnerabilities": many_cves}]}],
        "Misconfigurations": [{"Namespace": "a", "Kind": "Pod", "Name": "p",
                               "Results": [{"Target": "t", "Misconfigurations": many_checks}]}],
    }
    out = k8s_parse.parse_trivy_k8s_result(_raw(report_text=json.dumps(report)))
    assert out["total_vulnerabilities"] == 150
    assert len(out["vulnerabilities"]) == 100
    assert out["vulnerabilities_truncated"] is True
    assert out["total_misconfigurations"] == 120
    assert len(out["misconfigurations"]) == 100
    assert out["misconfigurations_truncated"] is True


def test_clean_cluster_is_success_with_zero_findings_and_note():
    empty = json.dumps({"ClusterName": "clean", "Vulnerabilities": [], "Misconfigurations": []})
    out = k8s_parse.parse_trivy_k8s_result(_raw(report_text=empty))
    assert out["status"] == "success"
    assert out["total_misconfigurations"] == 0
    assert out["total_vulnerabilities"] == 0
    assert "notes" in out and "error" not in out


def test_malformed_sections_yield_no_rows_not_an_exception():
    weird = json.dumps({
        "Vulnerabilities": "not-a-list",
        "Misconfigurations": [None, {"Results": [{"Misconfigurations": [None, "x"]}]}],
    })
    out = k8s_parse.parse_trivy_k8s_result(_raw(report_text=weird))
    assert out["status"] == "success"
    assert out["total_misconfigurations"] == 0


def test_nonzero_exit_is_failed_status():
    out = k8s_parse.parse_trivy_k8s_result(_raw(returncode=1, stderr="connection refused"))
    assert out["status"] == "failed"
    assert "exited with code 1" in out["error"]
    assert "connection refused" in out["error"]


def test_unparseable_report_is_failed_status():
    out = k8s_parse.parse_trivy_k8s_result(_raw(report_text="not json"))
    assert out["status"] == "failed"


# ---------------------------------------------------------------------------
# Tool wrapper
# ---------------------------------------------------------------------------

def test_tool_run_returns_parsed_result_without_private_report_key(tmp_path):
    kc = _kubeconfig(tmp_path)
    captured = {}
    with patch.object(k8s_execute.subprocess, "run",
                      side_effect=_fake_run_writing(json.dumps(REPORT_FIXTURE), captured)):
        out = TrivyK8sScan().run(kubeconfig=kc, namespace="payments")
    assert out["status"] == "success"
    assert "_report" not in out
    assert "_full_evidence" in out  # left for extract_evidence() to pop
    assert out["namespace"] == "payments"


def test_extract_evidence_keys_on_cluster_scope_and_pops_full_report(tmp_path):
    tool = TrivyK8sScan()
    kc = _kubeconfig(tmp_path)
    captured = {}
    with patch.object(k8s_execute.subprocess, "run",
                      side_effect=_fake_run_writing(json.dumps(REPORT_FIXTURE), captured)):
        out = tool.run(kubeconfig=kc)
    evidence = tool.extract_evidence({"kubeconfig": kc}, out)
    assert evidence is not None
    key, data = evidence
    assert key == "k8s:default/all"
    assert data["report"]["ClusterName"] == "kind-tradecraft-lab"
    assert "_full_evidence" not in out


def test_extract_facts_is_empty_for_cluster_findings():
    assert TrivyK8sScan().extract_facts({}, {"status": "success"}) == []


def test_tool_is_available_reflects_binary_on_path():
    with patch.object(k8s_execute.shutil, "which", return_value="/usr/bin/trivy"):
        assert TrivyK8sScan().is_available() is True
    with patch.object(k8s_execute.shutil, "which", return_value=None):
        assert TrivyK8sScan().is_available() is False
