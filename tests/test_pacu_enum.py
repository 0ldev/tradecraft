"""
Unit tests for the pacu_enum adapter, parser, Tool wrapper, and contract.

Fixtures are real captured output from Pacu 1.7.0 on CT 115 (`pacu -q
--new-session <name> --set-keys tradecraft_key,<fake-key>,<fake-secret>
--module-name <module> [--module-args=...] --exec`, run inside a
disposable HOME, against an intentionally invalid/fake credential so no
real AWS account is touched), not hand-typed shapes.
"""
from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

from tradecraft.adapters.pacu_enum import execute as pacu_execute
from tradecraft.adapters.pacu_enum import parse as pacu_parse
from tradecraft.adapters.pacu_enum.parse import RawPacuEnumResult
from tradecraft.tools.pacu_enum import PacuEnum
from tradecraft.tools.profiles import load_profile

FAKE_CREDENTIAL = "AKIAFAKE1234567890:fakeSecretKeyValue1234567890fakefake"

# Real capture: iam__enum_permissions against an invalid key.
REAL_ENUM_PERMISSIONS_INVALID_TOKEN = """\
No database found at /tmp/pacu_enum_home_2mfj3hrx/.local/share/pacu/sqlite.db
Database created at /tmp/pacu_enum_home_2mfj3hrx/.local/share/pacu/sqlite.db

Session tradecraft_b3efdca2aa created.
  Running module iam__enum_permissions...
"""
REAL_ENUM_PERMISSIONS_INVALID_TOKEN_STDERR = """\
Traceback (most recent call last):
  File "/root/.local/bin/pacu", line 6, in <module>
    sys.exit(main())
  File "/root/.local/pipx/venvs/pacu/lib/python3.11/site-packages/pacu/__main__.py", line 10, in main
    pacu.Main().run()
  File "/root/.local/pipx/venvs/pacu/lib/python3.11/site-packages/pacu/main.py", line 2062, in run
    self.run_cli(args)
  File "/root/.local/pipx/venvs/pacu/lib/python3.11/site-packages/pacu/main.py", line 1890, in run_cli
    self.exec_module(module)
  File "/root/.local/pipx/venvs/pacu/lib/python3.11/site-packages/pacu/main.py", line 1082, in exec_module
    summary_data = module.main(command[2:], self)
  File "/root/.local/pipx/venvs/pacu/lib/python3.11/site-packages/pacu/modules/iam__enum_permissions/main.py", line 161, in main
    identity = client.get_caller_identity()
  File "/root/.local/pipx/venvs/pacu/lib/python3.11/site-packages/botocore/client.py", line 535, in _api_call
    return self._make_api_call(operation_name, kwargs)
  File "/root/.local/pipx/venvs/pacu/lib/python3.11/site-packages/botocore/client.py", line 983, in _make_api_call
    raise error_class(parsed_response, operation_name)
botocore.exceptions.ClientError: An error occurred (InvalidClientTokenId) when calling the GetCallerIdentity operation: The security token included in the request is invalid.
"""

# Real capture: s3__download_bucket --names-only against an invalid key.
REAL_S3_LIST_INVALID_KEY = """\
No database found at /tmp/pacu_enum_home_madusjvz/.local/share/pacu/sqlite.db
Database created at /tmp/pacu_enum_home_madusjvz/.local/share/pacu/sqlite.db

Session tradecraft_52a97b1064 created.
  Running module s3__download_bucket...
[s3__download_bucket] Enumerating buckets...
[s3__download_bucket] InvalidAccessKeyId
[s3__download_bucket] s3__download_bucket completed.

[s3__download_bucket] MODULE SUMMARY:

  No actions were taken.
"""

# Synthetic but format-verified against iam__enum_permissions' own module
# source (MODULE SUMMARY block) -- no real AWS account was available to
# produce this branch live; the single/plural line regexes above were
# built directly from that source, not guessed.
SYNTHETIC_ENUM_PERMISSIONS_SUCCESS = """\
  Running module iam__enum_permissions...
iam__enum_permissions completed.

MODULE SUMMARY:

  2 Confirmed permissions for user: tradecraft-test.
  1 Unconfirmed permissions for user: tradecraft-test.
"""

SYNTHETIC_PRIVESC_SCAN_METHODS = """\
  Running module iam__privesc_scan...
  CONFIRMED: CreateNewPolicyVersion
  POTENTIAL: UpdateRolePolicyToAssumeIt
  Scan Complete
"""


def test_redact_credentials_replaces_both_secret_components():
    text = "key tradecraft_key,AKIAFAKE1234567890,fakeSecretKeyValue1234567890fakefake end"
    redacted = pacu_parse.redact_credentials(text, FAKE_CREDENTIAL)
    assert "AKIAFAKE1234567890" not in redacted
    assert "fakeSecretKeyValue1234567890fakefake" not in redacted
    assert "<redacted>" in redacted


def test_redact_credentials_handles_empty_input():
    assert pacu_parse.redact_credentials("", FAKE_CREDENTIAL) == ""
    assert pacu_parse.redact_credentials("text", "") == "text"


def test_parse_enum_permissions_invalid_token_is_an_error():
    raw = RawPacuEnumResult(
        target="probe", action="enum_permissions", session="tradecraft_b3efdca2aa",
        stdout=REAL_ENUM_PERMISSIONS_INVALID_TOKEN,
        stderr=REAL_ENUM_PERMISSIONS_INVALID_TOKEN_STDERR, returncode=1,
    )
    result = pacu_parse.parse_pacu_enum_result(raw)
    assert result["status"] == "failed"
    assert result["action"] == "enum_permissions"
    assert "InvalidClientTokenId" in result["error"]
    assert "GetCallerIdentity" in result["error"]


def test_parse_s3_list_invalid_key_is_an_error():
    raw = RawPacuEnumResult(
        target="probe", action="s3_list", session="tradecraft_52a97b1064",
        stdout=REAL_S3_LIST_INVALID_KEY, stderr="", returncode=0,
        names_text="",
    )
    result = pacu_parse.parse_pacu_enum_result(raw)
    assert result["status"] == "failed"
    assert result["error"] == "AWS credential error: InvalidAccessKeyId"


def test_parse_enum_permissions_success_counts_subjects():
    raw = RawPacuEnumResult(
        target="probe", action="enum_permissions", session="s1",
        stdout=SYNTHETIC_ENUM_PERMISSIONS_SUCCESS, stderr="", returncode=0,
    )
    result = pacu_parse.parse_pacu_enum_result(raw)
    assert result["status"] == "success"
    assert result["users_confirmed"] == 1
    assert result["users_confirmed_permission_count"] == 2
    assert result["users_unconfirmed_permission_count"] == 1
    assert "tradecraft-test" in result["subjects"]


def test_parse_privesc_scan_success_lists_methods():
    raw = RawPacuEnumResult(
        target="probe", action="privesc_scan", session="s1",
        stdout=SYNTHETIC_PRIVESC_SCAN_METHODS, stderr="", returncode=0,
    )
    result = pacu_parse.parse_pacu_enum_result(raw)
    assert result["status"] == "success"
    assert result["confirmed_methods"] == ["CreateNewPolicyVersion"]
    assert result["potential_methods"] == ["UpdateRolePolicyToAssumeIt"]
    assert result["scan_complete"] is True


def test_parse_s3_list_success_extracts_bucket_names_and_objects():
    stdout = (
        '  Running module s3__download_bucket...\n'
        '[s3__download_bucket] Found bucket "tradecraft-test-bucket"\n'
        '[s3__download_bucket] 1 total buckets found.\n'
        '[s3__download_bucket] 1 buckets found with read permissions.\n'
    )
    raw = RawPacuEnumResult(
        target="probe", action="s3_list", session="s1",
        stdout=stdout, stderr="", returncode=0,
        names_text="secret.txt@tradecraft-test-bucket\n",
    )
    result = pacu_parse.parse_pacu_enum_result(raw)
    assert result["status"] == "success"
    assert result["buckets"] == 1
    assert result["readable_buckets"] == 1
    assert result["bucket_names"] == ["tradecraft-test-bucket"]
    assert result["objects_sample"] == ["secret.txt@tradecraft-test-bucket"]


def test_parse_s3_object_entry_splits_key_and_bucket():
    assert pacu_parse.parse_s3_object_entry("a/b.txt@my-bucket") == {
        "key": "a/b.txt", "bucket": "my-bucket",
    }
    assert pacu_parse.parse_s3_object_entry("not-an-entry") is None


def test_unsupported_action_is_a_clean_failure():
    raw = RawPacuEnumResult(target="probe", action="delete_everything", session="s1")
    result = pacu_parse.parse_pacu_enum_result(raw)
    assert result["status"] == "failed"
    assert "unsupported pacu_enum action" in result["error"]


def test_execute_rejects_malformed_credential_without_calling_subprocess():
    with patch("subprocess.run") as run:
        raw = pacu_execute.execute(target="probe", action="enum_permissions", credential="not-valid")
    run.assert_not_called()
    assert raw.error == "credential must be 'AccessKeyId:SecretAccessKey[:SessionToken]'"


def test_execute_rejects_unsupported_action_without_calling_subprocess():
    with patch("subprocess.run") as run:
        raw = pacu_execute.execute(target="probe", action="bogus", credential=FAKE_CREDENTIAL)
    run.assert_not_called()
    assert "unsupported pacu_enum action" in raw.error


def test_execute_enum_permissions_argv_uses_set_keys_and_equals_joined_module_args():
    process = subprocess.CompletedProcess([], 1, stdout=REAL_ENUM_PERMISSIONS_INVALID_TOKEN,
                                           stderr=REAL_ENUM_PERMISSIONS_INVALID_TOKEN_STDERR)
    with patch("subprocess.run", return_value=process) as run:
        raw = pacu_execute.execute(target="probe", action="enum_permissions", credential=FAKE_CREDENTIAL)

    run.assert_called_once()
    argv = run.call_args[0][0]
    assert argv[0] == "pacu"
    assert "-q" in argv
    assert "--new-session" in argv
    assert "--set-keys" in argv
    set_keys_value = argv[argv.index("--set-keys") + 1]
    assert set_keys_value.split(",")[1:] == ["AKIAFAKE1234567890", "fakeSecretKeyValue1234567890fakefake"]
    assert "--module-name" in argv
    assert argv[argv.index("--module-name") + 1] == "iam__enum_permissions"
    assert "--exec" in argv
    assert not any(a == "--module-args" for a in argv)
    assert raw.returncode == 1
    assert raw.stdout == process.stdout


def test_execute_privesc_scan_short_circuits_on_prereq_failure():
    process = subprocess.CompletedProcess([], 1, stdout=REAL_ENUM_PERMISSIONS_INVALID_TOKEN,
                                           stderr=REAL_ENUM_PERMISSIONS_INVALID_TOKEN_STDERR)
    with patch("subprocess.run", return_value=process) as run:
        raw = pacu_execute.execute(target="probe", action="privesc_scan", credential=FAKE_CREDENTIAL)

    run.assert_called_once()
    argv = run.call_args[0][0]
    assert argv[argv.index("--module-name") + 1] == "iam__enum_permissions"
    assert raw.returncode == 1
    assert raw.action == "privesc_scan"


def test_execute_privesc_scan_runs_module_args_after_successful_prereq():
    prereq_ok = subprocess.CompletedProcess([], 0, stdout="ok", stderr="")
    scan_ok = subprocess.CompletedProcess([], 0, stdout=SYNTHETIC_PRIVESC_SCAN_METHODS, stderr="")
    with patch("subprocess.run", side_effect=[prereq_ok, scan_ok]) as run:
        raw = pacu_execute.execute(target="probe", action="privesc_scan", credential=FAKE_CREDENTIAL)

    assert run.call_count == 2
    second_argv = run.call_args_list[1][0][0]
    assert "--module-args=--scan-only" in second_argv
    assert "--session" in second_argv
    assert "--new-session" not in second_argv
    assert raw.stdout == SYNTHETIC_PRIVESC_SCAN_METHODS


def test_execute_s3_list_uses_names_only_module_args():
    process = subprocess.CompletedProcess([], 0, stdout=REAL_S3_LIST_INVALID_KEY, stderr="")
    with patch("subprocess.run", return_value=process) as run, \
         patch("pathlib.Path.exists", return_value=False):
        raw = pacu_execute.execute(target="probe", action="s3_list", credential=FAKE_CREDENTIAL)

    argv = run.call_args[0][0]
    assert "--module-args=--names-only" in argv
    assert argv[argv.index("--module-name") + 1] == "s3__download_bucket"
    assert raw.names_text == ""


def test_execute_missing_binary_and_timeout_are_reported():
    with patch("subprocess.run", side_effect=FileNotFoundError()):
        raw = pacu_execute.execute(target="probe", action="enum_permissions", credential=FAKE_CREDENTIAL)
    assert raw.error == "pacu executable not found on PATH"

    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("pacu", 300)):
        raw = pacu_execute.execute(target="probe", action="enum_permissions", credential=FAKE_CREDENTIAL)
    assert raw.error == "pacu timed out after 300s"


def test_is_available_reflects_shutil_which():
    with patch("shutil.which", return_value="/root/.local/bin/pacu"):
        assert pacu_execute.is_available() is True
    with patch("shutil.which", return_value=None):
        assert pacu_execute.is_available() is False


def test_tool_run_redacts_credential_from_evidence_transcript():
    process = subprocess.CompletedProcess(
        [], 1, stdout="Session s1 created.\ntradecraft_key,AKIAFAKE1234567890,fakeSecretKeyValue1234567890fakefake\n",
        stderr=REAL_ENUM_PERMISSIONS_INVALID_TOKEN_STDERR,
    )
    with patch("subprocess.run", return_value=process):
        result = PacuEnum().run(target="probe", action="enum_permissions", credential=FAKE_CREDENTIAL)

    transcript = result["_full_evidence"]["transcript"]
    assert "AKIAFAKE1234567890" not in transcript
    assert "fakeSecretKeyValue1234567890fakefake" not in transcript
    assert result["status"] == "failed"


def test_tool_extract_evidence_and_facts_on_success():
    tool = PacuEnum()
    result = {
        "target": "probe.example", "action": "enum_permissions", "mode": "enum",
        "status": "success", "users_confirmed": 1, "roles_confirmed": 0,
        "_full_evidence": {"target": "probe.example", "transcript": "ok"},
    }
    evidence = tool.extract_evidence({"target": "probe.example"}, result)
    assert evidence == ("probe.example", {"target": "probe.example", "transcript": "ok"})
    assert "_full_evidence" not in result

    result["evidence_id"] = "pacu_enum:probe.example"
    facts = tool.extract_facts({"target": "probe.example"}, result)
    assert len(facts) == 1
    fact = facts[0]
    assert fact["aws_iam_enum_tested"] is True
    assert fact["aws_iam_subjects_confirmed"] == 1
    assert fact["evidence"] == "pacu_enum:probe.example"


def test_tool_extract_facts_empty_on_failure():
    tool = PacuEnum()
    result = {"target": "probe.example", "action": "enum_permissions", "status": "failed", "error": "x"}
    assert tool.extract_facts({"target": "probe.example"}, result) == []


def test_tool_id_and_profile_membership():
    tool = PacuEnum()
    assert tool.tool_id == "pacu_enum"
    cloud_profile = load_profile("cloud")
    assert "pacu_enum" in cloud_profile
    web_profile = load_profile("web")
    assert "pacu_enum" in web_profile
