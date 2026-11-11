"""
Unit tests for the scoutsuite_audit adapter, parser, Tool wrapper, and contract.

Argv shapes were confirmed against the real ScoutSuite 5.14.0 CLI on CT 115
(`scout aws --help`, `scout azure --help`, `scout gcp --help`). The report
layout (`<report-dir>/scoutsuite-results/scoutsuite_results_<name>.js`, first
line `scoutsuite_results =`) was confirmed from the installed package's
output/utils.py. The report fixture below mirrors that shape. No test here
calls a real cloud API: subprocess.run is mocked everywhere it would reach
scout.
"""
from __future__ import annotations

import base64
import json
import os
import stat
import subprocess
from unittest.mock import MagicMock, patch

from tradecraft.adapters.scoutsuite_audit import execute as scout_execute
from tradecraft.adapters.scoutsuite_audit import parse as scout_parse
from tradecraft.adapters.scoutsuite_audit.parse import RawScoutSuiteResult
from tradecraft.tools.scoutsuite_audit import ScoutsuiteAudit
from tradecraft.tools.profiles import load_profile

AWS_CRED = "AKIAFAKE1234567890:fakeSecretKeyValue1234567890fakefake"
AWS_CRED_TOKEN = AWS_CRED + ":FAKESESSIONTOKENabcdef"
AZURE_CRED = "11111111-aaaa-bbbb-cccc-000000000000:22222222-aaaa-bbbb-cccc-111111111111:fakeClientSecret~abc"
AZURE_CRED_SUB = AZURE_CRED + ":33333333-aaaa-bbbb-cccc-222222222222"

GCP_KEY = {
    "type": "service_account",
    "project_id": "fake-project-123",
    "private_key_id": "fakekeyid0000000000000000000000000000",
    "private_key": "-----BEGIN PRIVATE KEY-----\nFAKEFAKEFAKE\n-----END PRIVATE KEY-----\n",
    "client_email": "tradecraft-test@fake-project-123.iam.gserviceaccount.com",
    "client_id": "100000000000000000000",
    "token_uri": "https://oauth2.googleapis.com/token",
}
GCP_RAW = json.dumps(GCP_KEY)
GCP_B64 = base64.b64encode(GCP_RAW.encode()).decode()


def _report_js(services: dict) -> str:
    """Matches ScoutSuite's JavaScriptEncoder output: a first line of
    `scoutsuite_results =` followed by the JSON payload."""
    payload = {
        "last_run": {"provider": "aws", "time": "2026-11-04 00:00:00"},
        "services": services,
    }
    return "scoutsuite_results =\n" + json.dumps(payload, indent=4) + ";\n"


def _rule(level: str, flagged: int, checked: int = 5, description: str = "d") -> dict:
    return {
        "description": description,
        "level": level,
        "flagged_items": flagged,
        "checked_items": checked,
        "items": [f"item-{i}" for i in range(flagged)],
    }


REAL_SHAPED_REPORT_JS = _report_js({
    "s3": {
        "findings": {
            "s3-bucket-world-readable": _rule("danger", 2, 9, "Bucket readable by everyone"),
            "s3-bucket-logging-disabled": _rule("warning", 1, 9, "Access logging disabled"),
            "s3-bucket-encryption-ok": _rule("warning", 0, 9, "All buckets encrypted"),
        }
    },
    "ec2": {
        "findings": {
            "ec2-sg-open-ssh": _rule("danger", 1, 14, "SSH open to 0.0.0.0/0"),
            "ec2-unused-eip": _rule("warning", 3, 14, "Unattached elastic IPs"),
        }
    },
    "iam": {
        "findings": {
            "iam-root-no-mfa": _rule("danger", 1, 1, "Root without MFA"),
            "iam-user-no-mfa": _rule("warning", 0, 22, "Console users without MFA"),
        }
    },
})


def _ok_raw(report_text: str = REAL_SHAPED_REPORT_JS, provider: str = "aws") -> RawScoutSuiteResult:
    return RawScoutSuiteResult(
        target="acct-1", provider=provider, stdout="", stderr="",
        returncode=0, report_text=report_text,
    )


def _completed(returncode: int = 0, stdout: str = "", stderr: str = "") -> MagicMock:
    proc = MagicMock(spec=subprocess.CompletedProcess)
    proc.returncode = returncode
    proc.stdout = stdout
    proc.stderr = stderr
    return proc


def _run_with_report(report_text: str = REAL_SHAPED_REPORT_JS, returncode: int = 0):
    """Patches subprocess.run so that the fake scout writes `report_text` into
    the --report-dir it was given, the way the real CLI does."""
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        report_dir = argv[argv.index("--report-dir") + 1]
        out_dir = os.path.join(report_dir, "scoutsuite-results")
        os.makedirs(out_dir, exist_ok=True)
        with open(os.path.join(out_dir, "scoutsuite_results_aws-123456789012.js"), "w") as fh:
            fh.write(report_text)
        return _completed(returncode=returncode)

    return captured, fake_run


# ---------------------------------------------------------------------------
# Contract and profile placement
# ---------------------------------------------------------------------------

def test_contract_declares_expected_fields():
    tool = ScoutsuiteAudit()
    assert tool.tool_id == "scoutsuite_audit"
    assert tool.required_binary == "scout"
    assert tool.scope_param == "target"
    assert tool.destructive is False


def test_contract_declares_provider_credential_and_services_params():
    from tradecraft.tools.spec_loader import declared_parameter_names

    names = declared_parameter_names("scoutsuite_audit")
    assert {"target", "provider", "credential", "services"} <= names


def test_scoutsuite_audit_in_cloud_and_web_profiles():
    assert "scoutsuite_audit" in load_profile("cloud")
    assert "scoutsuite_audit" in load_profile("web")


# ---------------------------------------------------------------------------
# Adapter: provider and credential validation (no subprocess should run)
# ---------------------------------------------------------------------------

def test_unknown_provider_returns_error_without_running_scout():
    with patch.object(scout_execute.subprocess, "run") as run:
        raw = scout_execute.execute("t", "oracle", AWS_CRED)
    run.assert_not_called()
    assert raw.error and "provider must be one of" in raw.error


def test_aws_single_component_credential_is_rejected():
    with patch.object(scout_execute.subprocess, "run") as run:
        raw = scout_execute.execute("t", "aws", "AKIAONLYKEY")
    run.assert_not_called()
    assert raw.error == "credential must be 'AccessKeyId:SecretAccessKey[:SessionToken]'"


def test_aws_too_many_components_is_rejected():
    with patch.object(scout_execute.subprocess, "run") as run:
        raw = scout_execute.execute("t", "aws", "a:b:c:d")
    run.assert_not_called()
    assert raw.error is not None


def test_azure_credential_with_only_two_components_is_rejected():
    with patch.object(scout_execute.subprocess, "run") as run:
        raw = scout_execute.execute("t", "azure", "tenant:client")
    run.assert_not_called()
    assert raw.error == "credential must be 'TenantId:ClientId:ClientSecret[:SubscriptionId]'"


def test_gcp_non_json_credential_is_rejected():
    with patch.object(scout_execute.subprocess, "run") as run:
        raw = scout_execute.execute("t", "gcp", "not json at all")
    run.assert_not_called()
    assert raw.error is not None and "service-account JSON" in raw.error


def test_invalid_services_value_is_rejected_without_running_scout():
    with patch.object(scout_execute.subprocess, "run") as run:
        raw = scout_execute.execute("t", "aws", AWS_CRED, services="s3;rm -rf /")
    run.assert_not_called()
    assert raw.error is not None and "services" in raw.error


# ---------------------------------------------------------------------------
# Adapter: AWS argv (confirmed flags from `scout aws --help`)
# ---------------------------------------------------------------------------

def test_aws_access_keys_argv_without_session_token():
    captured, fake_run = _run_with_report()
    with patch.object(scout_execute.subprocess, "run", side_effect=fake_run):
        raw = scout_execute.execute("acct-1", "aws", AWS_CRED)
    argv = captured["argv"]
    assert raw.error is None
    assert argv[:2] == ["scout", "aws"]
    assert "--access-keys" in argv
    assert argv[argv.index("--access-key-id") + 1] == "AKIAFAKE1234567890"
    assert argv[argv.index("--secret-access-key") + 1] == "fakeSecretKeyValue1234567890fakefake"
    assert "--session-token" not in argv
    assert "--no-browser" in argv
    assert argv[argv.index("--max-workers") + 1] == "10"
    assert "--report-dir" in argv
    assert "--services" not in argv


def test_aws_argv_includes_session_token_when_provided():
    captured, fake_run = _run_with_report()
    with patch.object(scout_execute.subprocess, "run", side_effect=fake_run):
        scout_execute.execute("acct-1", "aws", AWS_CRED_TOKEN)
    argv = captured["argv"]
    assert argv[argv.index("--session-token") + 1] == "FAKESESSIONTOKENabcdef"


def test_aws_services_are_passed_as_separate_argv_tokens():
    captured, fake_run = _run_with_report()
    with patch.object(scout_execute.subprocess, "run", side_effect=fake_run):
        scout_execute.execute("acct-1", "aws", AWS_CRED, services="s3,ec2,iam")
    argv = captured["argv"]
    idx = argv.index("--services")
    assert argv[idx + 1: idx + 4] == ["s3", "ec2", "iam"]


def test_subprocess_is_hard_capped_at_600_seconds_with_disposable_home():
    captured, fake_run = _run_with_report()
    with patch.object(scout_execute.subprocess, "run", side_effect=fake_run):
        scout_execute.execute("acct-1", "aws", AWS_CRED)
    kwargs = captured["kwargs"]
    assert kwargs["timeout"] == 600
    assert kwargs["stdin"] == subprocess.DEVNULL
    home = kwargs["env"]["HOME"]
    assert os.path.basename(home) == "home"
    assert "scoutsuite_audit_" in home
    # The disposable tree is removed once execute() returns.
    assert not os.path.exists(home)


def test_timeout_surfaces_as_error_not_exception():
    with patch.object(
        scout_execute.subprocess, "run",
        side_effect=subprocess.TimeoutExpired(cmd="scout", timeout=600),
    ):
        raw = scout_execute.execute("acct-1", "aws", AWS_CRED)
    assert raw.error == "scout timed out after 600s"


def test_missing_binary_surfaces_as_error_not_exception():
    with patch.object(scout_execute.subprocess, "run", side_effect=FileNotFoundError()):
        raw = scout_execute.execute("acct-1", "aws", AWS_CRED)
    assert raw.error == "scout executable not found on PATH"


def test_secret_components_are_redacted_from_captured_output():
    def fake_run(argv, **kwargs):
        return _completed(
            returncode=1,
            stderr="botocore: InvalidClientTokenId for AKIAFAKE1234567890 / fakeSecretKeyValue1234567890fakefake",
        )

    with patch.object(scout_execute.subprocess, "run", side_effect=fake_run):
        raw = scout_execute.execute("acct-1", "aws", AWS_CRED)
    assert "AKIAFAKE1234567890" not in raw.stderr
    assert "fakeSecretKeyValue1234567890fakefake" not in raw.stderr
    assert "<redacted>" in raw.stderr


# ---------------------------------------------------------------------------
# Adapter: Azure argv (confirmed flags from `scout azure --help`)
# ---------------------------------------------------------------------------

def test_azure_service_principal_argv_without_subscription():
    captured, fake_run = _run_with_report()
    with patch.object(scout_execute.subprocess, "run", side_effect=fake_run):
        raw = scout_execute.execute("tenant-x", "azure", AZURE_CRED)
    argv = captured["argv"]
    assert raw.error is None
    assert argv[:3] == ["scout", "azure", "--service-principal"]
    assert argv[argv.index("--tenant") + 1] == "11111111-aaaa-bbbb-cccc-000000000000"
    assert argv[argv.index("--client-id") + 1] == "22222222-aaaa-bbbb-cccc-111111111111"
    assert argv[argv.index("--client-secret") + 1] == "fakeClientSecret~abc"
    assert "--subscriptions" not in argv


def test_azure_argv_includes_subscription_when_provided():
    captured, fake_run = _run_with_report()
    with patch.object(scout_execute.subprocess, "run", side_effect=fake_run):
        scout_execute.execute("tenant-x", "azure", AZURE_CRED_SUB)
    argv = captured["argv"]
    assert argv[argv.index("--subscriptions") + 1] == "33333333-aaaa-bbbb-cccc-222222222222"


# ---------------------------------------------------------------------------
# Adapter: GCP argv and base64/raw detection
# ---------------------------------------------------------------------------

def _gcp_service_account_path_seen(credential: str):
    """Runs execute() for gcp and returns (raw_result, path_seen_during_call,
    mode_seen, contents_seen). The temp file must exist while scout runs."""
    seen = {}
    captured, fake_run = _run_with_report()

    def wrapped(argv, **kwargs):
        idx = argv.index("--service-account")
        path = argv[idx + 1]
        seen["path"] = path
        seen["exists"] = os.path.exists(path)
        seen["mode"] = stat.S_IMODE(os.stat(path).st_mode)
        with open(path) as fh:
            seen["contents"] = json.load(fh)
        seen["argv"] = argv
        return fake_run(argv, **kwargs)

    with patch.object(scout_execute.subprocess, "run", side_effect=wrapped):
        raw = scout_execute.execute("proj", "gcp", credential)
    return raw, seen


def test_gcp_raw_json_is_written_0600_and_passed_as_service_account():
    raw, seen = _gcp_service_account_path_seen(GCP_RAW)
    assert raw.error is None
    assert seen["argv"][:2] == ["scout", "gcp"]
    assert seen["argv"][seen["argv"].index("--service-account") + 1] == seen["path"]
    assert seen["exists"] is True
    assert seen["mode"] == 0o600
    assert seen["contents"] == GCP_KEY


def test_gcp_base64_json_is_decoded_and_written_0600():
    raw, seen = _gcp_service_account_path_seen(GCP_B64)
    assert raw.error is None
    assert seen["contents"] == GCP_KEY
    assert seen["mode"] == 0o600


def test_gcp_temp_file_is_removed_after_call():
    raw, seen = _gcp_service_account_path_seen(GCP_RAW)
    assert raw.error is None
    assert not os.path.exists(seen["path"])


def test_gcp_raw_json_with_colons_is_not_split():
    # Raw JSON contains colons; it must not go through the colon-split path.
    raw, seen = _gcp_service_account_path_seen(GCP_RAW)
    assert raw.error is None
    assert seen["contents"]["client_id"] == "100000000000000000000"


def test_gcp_json_that_is_not_service_account_is_rejected():
    not_sa = json.dumps({"type": "authorized_user", "client_id": "x"})
    with patch.object(scout_execute.subprocess, "run") as run:
        raw = scout_execute.execute("proj", "gcp", not_sa)
    run.assert_not_called()
    assert raw.error is not None and "service_account" in raw.error


def test_gcp_json_array_is_rejected():
    with patch.object(scout_execute.subprocess, "run") as run:
        raw = scout_execute.execute("proj", "gcp", json.dumps([GCP_KEY]))
    run.assert_not_called()
    assert raw.error is not None


def test_gcp_base64_of_non_service_account_json_is_rejected():
    encoded = base64.b64encode(json.dumps({"type": "other"}).encode()).decode()
    with patch.object(scout_execute.subprocess, "run") as run:
        raw = scout_execute.execute("proj", "gcp", encoded)
    run.assert_not_called()
    assert raw.error is not None


def test_gcp_file_path_is_not_accepted_as_credential():
    # A path is not JSON and not base64 of JSON, so it must be rejected
    # rather than handed to scout as a file the model chose.
    with patch.object(scout_execute.subprocess, "run") as run:
        raw = scout_execute.execute("proj", "gcp", "/etc/passwd")
    run.assert_not_called()
    assert raw.error is not None


def test_gcp_decode_order_base64_first_then_raw():
    # A valid base64 string that is not itself valid JSON must fall back to
    # the raw path, and fail there -- proving the order is base64-then-raw
    # without silently accepting undecodable input.
    assert scout_execute._decode_service_account("bm90IGpzb24=") is None
    # Raw JSON whose text is also valid base64 characters but is not base64
    # of JSON (contains braces) still decodes via the raw fallback.
    assert scout_execute._decode_service_account(GCP_RAW) == GCP_KEY
    assert scout_execute._decode_service_account(GCP_B64) == GCP_KEY


# ---------------------------------------------------------------------------
# Adapter: report-file discovery and execution errors
# ---------------------------------------------------------------------------

def test_missing_report_file_is_reported_as_failure():
    def fake_run(argv, **kwargs):
        return _completed(returncode=0)

    with patch.object(scout_execute.subprocess, "run", side_effect=fake_run):
        raw = scout_execute.execute("acct-1", "aws", AWS_CRED)
    result = scout_parse.parse_scoutsuite_result(raw)
    assert result["status"] == "failed"
    assert result["error"] == "scout produced no report file"


def test_report_glob_ignores_exceptions_and_errors_files():
    def fake_run(argv, **kwargs):
        report_dir = argv[argv.index("--report-dir") + 1]
        out_dir = os.path.join(report_dir, "scoutsuite-results")
        os.makedirs(out_dir, exist_ok=True)
        with open(os.path.join(out_dir, "scoutsuite_exceptions_aws-1.js"), "w") as fh:
            fh.write("exceptions =\n{}")
        return _completed(returncode=0)

    with patch.object(scout_execute.subprocess, "run", side_effect=fake_run):
        raw = scout_execute.execute("acct-1", "aws", AWS_CRED)
    assert raw.report_text == ""


# ---------------------------------------------------------------------------
# Parser: JS-prefix stripping, flagged-only extraction, severity sort, caps
# ---------------------------------------------------------------------------

def test_parse_report_js_strips_assignment_prefix_and_trailing_semicolon():
    parsed = scout_parse.parse_report_js(REAL_SHAPED_REPORT_JS)
    assert parsed is not None
    assert parsed["last_run"]["provider"] == "aws"
    assert "s3" in parsed["services"]


def test_parse_report_js_rejects_non_object_payloads():
    assert scout_parse.parse_report_js("") is None
    assert scout_parse.parse_report_js("scoutsuite_results = not-json;") is None
    assert scout_parse.parse_report_js("scoutsuite_results = [1,2,3];") is None


def test_only_flagged_rules_are_returned_and_zero_flag_rules_dropped():
    result = scout_parse.parse_scoutsuite_result(_ok_raw())
    rules = {(f["service"], f["rule"]) for f in result["findings"]}
    assert ("s3", "s3-bucket-encryption-ok") not in rules
    assert ("iam", "iam-user-no-mfa") not in rules
    assert ("s3", "s3-bucket-world-readable") in rules
    assert result["total_findings"] == 5
    assert result["truncated"] is False


def test_findings_are_sorted_danger_before_warning():
    result = scout_parse.parse_scoutsuite_result(_ok_raw())
    levels = [f["level"] for f in result["findings"]]
    assert levels == sorted(levels, key=lambda lvl: 0 if lvl == "danger" else 1)
    assert levels[:3] == ["danger", "danger", "danger"]
    assert levels[-2:] == ["warning", "warning"]


def test_finding_entry_shape():
    result = scout_parse.parse_scoutsuite_result(_ok_raw())
    first = result["findings"][0]
    assert set(first) == {
        "service", "rule", "level", "description", "flagged_items", "checked_items"
    }
    assert first["service"] in {"s3", "ec2", "iam"}


def test_findings_capped_at_100_with_total_and_truncated_flag():
    services = {
        "svc": {
            "findings": {
                f"rule-{i:03d}": _rule("warning", 1) for i in range(150)
            }
        }
    }
    result = scout_parse.parse_scoutsuite_result(_ok_raw(_report_js(services)))
    assert result["total_findings"] == 150
    assert len(result["findings"]) == scout_parse.MAX_FINDINGS_RETURNED == 100
    assert result["truncated"] is True


def test_clean_report_yields_zero_findings_with_note():
    clean = _report_js({"s3": {"findings": {"x": _rule("warning", 0)}}})
    result = scout_parse.parse_scoutsuite_result(_ok_raw(clean))
    assert result["status"] == "success"
    assert result["total_findings"] == 0
    assert result["findings"] == []
    assert result["truncated"] is False
    assert "notes" in result


def test_unparseable_report_is_a_failure_not_an_exception():
    result = scout_parse.parse_scoutsuite_result(_ok_raw("scoutsuite_results = {broken"))
    assert result["status"] == "failed"
    assert "not parseable" in result["error"]


def test_nonzero_exit_is_failure_with_tail():
    raw = RawScoutSuiteResult(
        target="t", provider="aws", returncode=2,
        stderr="usage: scout aws ...\nscout: error: unrecognized arguments: --bogus",
    )
    result = scout_parse.parse_scoutsuite_result(raw)
    assert result["status"] == "failed"
    assert result["error"].startswith("scout exited with code 2")
    assert "unrecognized arguments" in result["error"]


def test_evidence_under_cap_stores_full_report_dict():
    report = json.loads(REAL_SHAPED_REPORT_JS.split("=", 1)[1].rstrip().rstrip(";"))
    ev = scout_parse.build_full_evidence("t", "aws", report)
    assert ev["report"] == report
    assert "report_truncated" not in ev


def test_evidence_over_2mb_is_truncated_text():
    big = {"services": {"s": {"findings": {"r": {"description": "x" * (2_100_000)}}}}}
    ev = scout_parse.build_full_evidence("t", "aws", big)
    assert ev["report_truncated"] is True
    assert len(ev["report_json"]) == scout_parse.MAX_EVIDENCE_CHARS
    assert "report" not in ev


# ---------------------------------------------------------------------------
# Tool glue
# ---------------------------------------------------------------------------

def test_tool_run_stores_evidence_and_does_not_leak_private_keys():
    captured, fake_run = _run_with_report()
    with patch.object(scout_execute.subprocess, "run", side_effect=fake_run):
        result = ScoutsuiteAudit().run(target="acct-1", provider="aws", credential=AWS_CRED)
    assert "_report" not in result
    assert "_full_evidence" in result
    assert result["_full_evidence"]["provider"] == "aws"
    assert result["status"] == "success"


def test_extract_evidence_pops_full_evidence():
    tool = ScoutsuiteAudit()
    result = {"status": "success", "_full_evidence": {"report": {}}}
    ev = tool.extract_evidence({"target": "acct-1"}, result)
    assert ev == ("acct-1", {"report": {}})
    assert "_full_evidence" not in result


def test_extract_facts_reports_tested_and_flagged_counts():
    tool = ScoutsuiteAudit()
    facts = tool.extract_facts(
        {"target": "acct-1"},
        {"status": "success", "total_findings": 5},
    )
    assert len(facts) == 1
    assert facts[0]["cloud_audit_scoutsuite_tested"] is True
    assert facts[0]["cloud_audit_scoutsuite_flagged"] == 5


def test_extract_facts_empty_on_failure():
    tool = ScoutsuiteAudit()
    assert tool.extract_facts({"target": "acct-1"}, {"status": "failed"}) == []
