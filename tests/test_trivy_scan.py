"""
Unit tests for the trivy_scan adapter, parser, Tool wrapper, and contract.

Argv shape and the JSON report layout were confirmed against the real
trivy 0.71.2 binary on CT 115 (`trivy image --help`, and a real
`trivy image --format json alpine:3.19` run). The VULN_FIXTURE rows below
are copied field-for-field from that captured report. No test here pulls a
registry image: subprocess.run is mocked everywhere it would reach trivy.
"""
from __future__ import annotations

import os
import subprocess
from unittest.mock import patch

from tradecraft.adapters.trivy_scan import execute as trivy_execute
from tradecraft.adapters.trivy_scan import parse as trivy_parse
from tradecraft.adapters.trivy_scan.parse import RawTrivyResult
from tradecraft.tools.profiles import load_profile
from tradecraft.tools.spec_loader import load_destructive_flag, load_required_binary, load_scope_param, load_spec
from tradecraft.tools.trivy_scan import TrivyScan

IMAGE = "alpine:3.19"


def _vuln(vid, pkg, installed, fixed, severity, title, url):
    return {
        "VulnerabilityID": vid,
        "PkgName": pkg,
        "InstalledVersion": installed,
        "FixedVersion": fixed,
        "Status": "fixed",
        "PrimaryURL": url,
        "Title": title,
        "Severity": severity,
    }


# Field-for-field copy of the 10 vulnerability rows in the real
# `trivy image --format json alpine:3.19` output captured on CT 115.
VULN_FIXTURE = [
    _vuln("CVE-2024-58251", "busybox", "1.36.1-r20", "1.36.1-r21", "MEDIUM",
          "In netstat in BusyBox through 1.37.0, local users can launch of networ ...",
          "https://avd.aquasec.com/nvd/cve-2024-58251"),
    _vuln("CVE-2025-46394", "busybox", "1.36.1-r20", "1.36.1-r21", "LOW",
          "In tar in BusyBox through 1.37.0, a TAR archive can have filenames hid ...",
          "https://avd.aquasec.com/nvd/cve-2025-46394"),
    _vuln("CVE-2026-40200", "musl", "1.2.4_git20230717-r5", "1.2.4_git20230717-r6", "HIGH",
          "musl: musl libc: Arbitrary code execution and denial of service via stack-based memory corruption in qsort",
          "https://avd.aquasec.com/nvd/cve-2026-40200"),
    _vuln("CVE-2026-6042", "musl", "1.2.4_git20230717-r5", "1.2.4_git20230717-r6", "MEDIUM",
          "musl libc: GB18030 4-byte Decoder: musl libc: Denial of Service via inefficient algorithmic complexity in iconv",
          "https://avd.aquasec.com/nvd/cve-2026-6042"),
    _vuln("CVE-2026-40200", "musl-utils", "1.2.4_git20230717-r5", "1.2.4_git20230717-r6", "HIGH",
          "musl: musl libc: Arbitrary code execution and denial of service via stack-based memory corruption in qsort",
          "https://avd.aquasec.com/nvd/cve-2026-40200"),
    _vuln("CVE-2026-6042", "musl-utils", "1.2.4_git20230717-r5", "1.2.4_git20230717-r6", "MEDIUM",
          "musl libc: GB18030 4-byte Decoder: musl libc: Denial of Service via inefficient algorithmic complexity in iconv",
          "https://avd.aquasec.com/nvd/cve-2026-6042"),
    _vuln("CVE-2024-58251", "ssl_client", "1.36.1-r20", "1.36.1-r21", "MEDIUM",
          "In netstat in BusyBox through 1.37.0, local users can launch of networ ...",
          "https://avd.aquasec.com/nvd/cve-2024-58251"),
    _vuln("CVE-2025-46394", "ssl_client", "1.36.1-r20", "1.36.1-r21", "LOW",
          "In tar in BusyBox through 1.37.0, a TAR archive can have filenames hid ...",
          "https://avd.aquasec.com/nvd/cve-2025-46394"),
    _vuln("CVE-2024-58251", "busybox-binsh", "1.36.1-r20", "1.36.1-r21", "MEDIUM",
          "In netstat in BusyBox through 1.37.0, local users can launch of networ ...",
          "https://avd.aquasec.com/nvd/cve-2024-58251"),
    _vuln("CVE-2025-46394", "busybox-binsh", "1.36.1-r20", "1.36.1-r21", "LOW",
          "In tar in BusyBox through 1.37.0, a TAR archive can have filenames hid ...",
          "https://avd.aquasec.com/nvd/cve-2025-46394"),
]


def _report(vulns=None, results_target="alpine:3.19 (alpine 3.19.9)"):
    results = [{
        "Target": results_target,
        "Class": "os-pkgs",
        "Type": "alpine",
        "Vulnerabilities": vulns if vulns is not None else VULN_FIXTURE,
    }]
    return {
        "SchemaVersion": 2,
        "Trivy": {"Version": "0.71.2"},
        "ArtifactName": IMAGE,
        "ArtifactType": "container_image",
        "Results": results,
    }


def _import_json(report) -> str:
    import json
    return json.dumps(report)


def _completed(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def _fake_run_writing(report_text: str, captured: dict, returncode: int = 0,
                      stderr: str = "", stdout: str = ""):
    """Fake subprocess.run that writes `report_text` to the --output path
    trivy was given, the way the real binary does, and records argv/kwargs."""
    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        out_path = argv[argv.index("--output") + 1]
        if report_text is not None:
            with open(out_path, "w") as handle:
                handle.write(report_text)
        return _completed(returncode=returncode, stdout=stdout, stderr=stderr)
    return fake_run


# ---------------------------------------------------------------------------
# Contract and profile placement
# ---------------------------------------------------------------------------

def test_contract_declares_target_and_credential_params():
    spec = load_spec("trivy_scan")
    assert spec.name == "trivy_scan"
    assert load_required_binary("trivy_scan") == "trivy"
    assert load_scope_param("trivy_scan") == "target"
    assert load_destructive_flag("trivy_scan") is False


def test_credential_is_optional_and_target_is_required():
    import yaml
    from pathlib import Path
    contract = yaml.safe_load(
        (Path(__file__).resolve().parents[1] / "config" / "tools" / "trivy_scan.yaml").read_text()
    )
    assert contract["parameters"]["required"] == ["target"]
    assert "credential" in contract["parameters"]["properties"]


def test_trivy_scan_in_cloud_and_kubernetes_profiles_not_web():
    assert "trivy_scan" in load_profile("cloud")
    assert "trivy_scan" in load_profile("kubernetes")
    assert "trivy_scan" not in load_profile("web")


# ---------------------------------------------------------------------------
# Adapter: target and credential validation (no subprocess should run)
# ---------------------------------------------------------------------------

def test_empty_target_is_rejected_without_running_trivy():
    with patch.object(trivy_execute.subprocess, "run") as run:
        raw = trivy_execute.execute("")
    run.assert_not_called()
    assert raw.error and "container image reference" in raw.error


def test_flag_like_target_is_rejected_so_it_cannot_inject_a_trivy_flag():
    with patch.object(trivy_execute.subprocess, "run") as run:
        raw = trivy_execute.execute("--output=/etc/passwd")
    run.assert_not_called()
    assert raw.error and "container image reference" in raw.error


def test_target_with_whitespace_is_rejected():
    with patch.object(trivy_execute.subprocess, "run") as run:
        raw = trivy_execute.execute("alpine:3.19 --insecure")
    run.assert_not_called()
    assert raw.error


def test_overlong_target_is_rejected():
    with patch.object(trivy_execute.subprocess, "run") as run:
        raw = trivy_execute.execute("a" * 300)
    run.assert_not_called()
    assert raw.error


def test_credential_without_colon_is_rejected():
    with patch.object(trivy_execute.subprocess, "run") as run:
        raw = trivy_execute.execute(IMAGE, credential="justausername")
    run.assert_not_called()
    assert raw.error == "credential must be 'username:password' (both non-empty)"


def test_credential_with_empty_password_is_rejected():
    with patch.object(trivy_execute.subprocess, "run") as run:
        raw = trivy_execute.execute(IMAGE, credential="user:")
    run.assert_not_called()
    assert raw.error


# ---------------------------------------------------------------------------
# Adapter: argv and environment
# ---------------------------------------------------------------------------

def test_argv_without_credential_is_exact_and_read_only():
    captured: dict = {}
    with patch.object(trivy_execute.subprocess, "run",
                      side_effect=_fake_run_writing(_import_json(_report()), captured)):
        trivy_execute.execute(IMAGE)
    argv = captured["argv"]
    assert argv[:2] == ["trivy", "image"]
    assert argv[argv.index("--format") + 1] == "json"
    assert argv[argv.index("--scanners") + 1] == "vuln"
    assert argv[argv.index("--image-src") + 1] == "remote"
    assert "--list-all-pkgs=false" in argv
    assert "--no-progress" in argv
    assert "--skip-version-check" in argv
    assert argv[argv.index("--timeout") + 1] == "540s"
    assert argv[-1] == IMAGE
    # Nothing in argv carries a registry secret.
    assert "--username" not in argv and "--password" not in argv


def test_argv_has_no_credential_env_when_no_credential_given():
    captured: dict = {}
    with patch.dict(os.environ, {"TRIVY_USERNAME": "stray", "TRIVY_PASSWORD": "stray"}), \
            patch.object(trivy_execute.subprocess, "run",
                         side_effect=_fake_run_writing(_import_json(_report()), captured)):
        trivy_execute.execute(IMAGE)
    env = captured["kwargs"]["env"]
    assert "TRIVY_USERNAME" not in env
    assert "TRIVY_PASSWORD" not in env


def test_credential_is_passed_via_env_not_argv():
    captured: dict = {}
    with patch.object(trivy_execute.subprocess, "run",
                      side_effect=_fake_run_writing(_import_json(_report()), captured)):
        trivy_execute.execute(IMAGE, credential="svc-user:s3cr3t-pass")
    argv = captured["argv"]
    env = captured["kwargs"]["env"]
    assert env["TRIVY_USERNAME"] == "svc-user"
    assert env["TRIVY_PASSWORD"] == "s3cr3t-pass"
    assert "svc-user" not in argv
    assert "s3cr3t-pass" not in argv


def test_credential_splits_on_first_colon_only():
    captured: dict = {}
    with patch.object(trivy_execute.subprocess, "run",
                      side_effect=_fake_run_writing(_import_json(_report()), captured)):
        trivy_execute.execute(IMAGE, credential="user:pa:ss:word")
    env = captured["kwargs"]["env"]
    assert env["TRIVY_USERNAME"] == "user"
    assert env["TRIVY_PASSWORD"] == "pa:ss:word"


def test_subprocess_is_hard_capped_at_600_seconds_with_no_stdin():
    captured: dict = {}
    with patch.object(trivy_execute.subprocess, "run",
                      side_effect=_fake_run_writing(_import_json(_report()), captured)):
        trivy_execute.execute(IMAGE)
    kwargs = captured["kwargs"]
    assert kwargs["timeout"] == 600
    assert kwargs["stdin"] == subprocess.DEVNULL
    assert kwargs["capture_output"] is True


def test_default_cache_is_not_redirected_to_a_disposable_home():
    # The vuln DB is vendor data, deliberately persistent (~/.cache/trivy):
    # the child must inherit HOME unchanged rather than get a throwaway one.
    captured: dict = {}
    with patch.object(trivy_execute.subprocess, "run",
                      side_effect=_fake_run_writing(_import_json(_report()), captured)):
        trivy_execute.execute(IMAGE)
    assert captured["kwargs"]["env"].get("HOME") == os.environ.get("HOME")


def test_timeout_surfaces_as_error_not_exception():
    with patch.object(trivy_execute.subprocess, "run",
                      side_effect=subprocess.TimeoutExpired(cmd="trivy", timeout=600)):
        raw = trivy_execute.execute(IMAGE)
    assert raw.error == "trivy timed out after 600s"


def test_missing_binary_surfaces_as_error_not_exception():
    with patch.object(trivy_execute.subprocess, "run", side_effect=FileNotFoundError()):
        raw = trivy_execute.execute(IMAGE)
    assert raw.error == "trivy executable not found on PATH"


def test_credential_is_redacted_from_captured_output():
    captured: dict = {}
    with patch.object(trivy_execute.subprocess, "run",
                      side_effect=_fake_run_writing(
                          None, captured, returncode=1,
                          stderr="FATAL login svc-user with s3cr3t-pass denied")):
        raw = trivy_execute.execute(IMAGE, credential="svc-user:s3cr3t-pass")
    assert "s3cr3t-pass" not in raw.stderr
    assert "svc-user" not in raw.stderr
    assert raw.stderr.count("<redacted>") == 2


# ---------------------------------------------------------------------------
# Parser: real-shape report, sorting, caps, empty, errors
# ---------------------------------------------------------------------------

def _raw(report_text=None, returncode=0, stderr="", stdout="", error=None):
    return RawTrivyResult(
        target=IMAGE,
        stdout=stdout,
        stderr=stderr,
        returncode=returncode,
        error=error,
        report_text=_import_json(_report()) if report_text is None else report_text,
    )


def test_parse_real_shape_report_counts_and_sorts_by_severity():
    result = trivy_parse.parse_trivy_result(_raw())
    assert result["status"] == "success"
    assert result["target"] == IMAGE
    assert result["total_findings"] == 10
    assert result["truncated"] is False
    assert result["severity_counts"] == {
        "CRITICAL": 0, "HIGH": 2, "MEDIUM": 5, "LOW": 3, "UNKNOWN": 0,
    }
    findings = result["findings"]
    assert findings[0]["severity"] == "HIGH"
    assert findings[-1]["severity"] == "LOW"
    assert findings[0]["vulnerability_id"] == "CVE-2026-40200"
    assert findings[0]["fixed_version"] == "1.2.4_git20230717-r6"
    assert findings[0]["result_target"] == "alpine:3.19 (alpine 3.19.9)"
    assert "_report" in result  # popped by the Tool layer, not returned to the model


def test_findings_list_is_capped_with_truncation_flag():
    many = []
    for i in range(150):
        many.append(_vuln(f"CVE-2099-{i:05d}", f"pkg{i:03d}", "1.0", "1.1", "HIGH",
                          "t", f"https://example.invalid/{i}"))
    result = trivy_parse.parse_trivy_result(_raw(_import_json(_report(vulns=many))))
    assert result["total_findings"] == 150
    assert len(result["findings"]) == trivy_parse.MAX_FINDINGS_RETURNED == 100
    assert result["truncated"] is True
    assert result["severity_counts"]["HIGH"] == 150


def test_critical_sorts_before_high_before_medium_before_low():
    vulns = [
        _vuln("CVE-L", "a", "1", "2", "LOW", "t", "u"),
        _vuln("CVE-M", "b", "1", "2", "MEDIUM", "t", "u"),
        _vuln("CVE-C", "c", "1", "2", "CRITICAL", "t", "u"),
        _vuln("CVE-H", "d", "1", "2", "HIGH", "t", "u"),
    ]
    result = trivy_parse.parse_trivy_result(_raw(_import_json(_report(vulns=vulns))))
    assert [f["vulnerability_id"] for f in result["findings"]] == ["CVE-C", "CVE-H", "CVE-M", "CVE-L"]


def test_report_with_no_vulnerabilities_is_success_with_note():
    empty = {"SchemaVersion": 2, "Results": [{"Target": "hello:latest", "Class": "os-pkgs", "Type": "debian"}]}
    result = trivy_parse.parse_trivy_result(_raw(_import_json(empty)))
    assert result["status"] == "success"
    assert result["total_findings"] == 0
    assert result["findings"] == []
    assert result["truncated"] is False
    assert "notes" in result and "no known vulnerabilities" in result["notes"][0]


def test_report_with_no_results_key_is_success_with_zero_findings():
    result = trivy_parse.parse_trivy_result(_raw(_import_json({"SchemaVersion": 2})))
    assert result["status"] == "success"
    assert result["total_findings"] == 0


def test_nonzero_exit_is_failure_with_stderr_tail():
    raw = _raw(report_text="", returncode=1, stderr="line one\nFATAL: image not found\n")
    result = trivy_parse.parse_trivy_result(raw)
    assert result["status"] == "failed"
    assert result["error"] == "trivy exited with code 1: FATAL: image not found"


def test_missing_report_file_is_failure():
    result = trivy_parse.parse_trivy_result(_raw(report_text=""))
    assert result["status"] == "failed"
    assert result["error"] == "trivy produced no report file"


def test_unparseable_report_is_failure():
    result = trivy_parse.parse_trivy_result(_raw(report_text="not json at all"))
    assert result["status"] == "failed"
    assert "not parseable as JSON" in result["error"]


def test_raw_error_is_returned_as_failure_without_parsing():
    result = trivy_parse.parse_trivy_result(RawTrivyResult(target=IMAGE, error="trivy timed out after 600s"))
    assert result == {"target": IMAGE, "status": "failed", "error": "trivy timed out after 600s"}


def test_error_text_is_bounded():
    raw = RawTrivyResult(target=IMAGE, returncode=2, stderr="x" * 5000)
    result = trivy_parse.parse_trivy_result(raw)
    assert len(result["error"]) <= trivy_parse.MAX_ERROR_CHARS


def test_evidence_is_bounded_when_report_is_huge(monkeypatch):
    monkeypatch.setattr(trivy_parse, "MAX_EVIDENCE_CHARS", 100)
    evidence = trivy_parse.build_full_evidence(IMAGE, _report())
    assert evidence["report_truncated"] is True
    assert len(evidence["report_json"]) == 100


def test_full_evidence_keeps_whole_report_when_small():
    evidence = trivy_parse.build_full_evidence(IMAGE, _report())
    assert evidence == {"target": IMAGE, "report": _report()}


# ---------------------------------------------------------------------------
# Tool layer
# ---------------------------------------------------------------------------

def test_tool_run_returns_model_result_without_private_keys_and_stores_evidence():
    captured: dict = {}
    tool = TrivyScan()
    with patch.object(trivy_execute.subprocess, "run",
                      side_effect=_fake_run_writing(_import_json(_report()), captured)):
        result = tool.run(target=IMAGE)
    assert result["status"] == "success"
    assert "_report" not in result
    assert "_full_evidence" in result  # extract_evidence pops it before the model sees it
    evidence = tool.extract_evidence({"target": IMAGE}, result)
    assert evidence == (IMAGE, {"target": IMAGE, "report": _report()})
    assert "_full_evidence" not in result


def test_tool_run_failure_has_no_evidence():
    tool = TrivyScan()
    with patch.object(trivy_execute.subprocess, "run", side_effect=FileNotFoundError()):
        result = tool.run(target=IMAGE)
    assert result["status"] == "failed"
    assert tool.extract_evidence({"target": IMAGE}, result) is None


def test_tool_extract_facts_is_empty_for_image_references():
    tool = TrivyScan()
    result = {"status": "success", "total_findings": 10}
    assert tool.extract_facts({"target": IMAGE}, result) == []


def test_tool_is_unavailable_without_trivy_on_path():
    with patch.object(trivy_execute.shutil, "which", return_value=None):
        assert TrivyScan().is_available() is False
    with patch.object(trivy_execute.shutil, "which", return_value="/usr/bin/trivy"):
        assert TrivyScan().is_available() is True
