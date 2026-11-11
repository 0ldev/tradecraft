"""
Unit tests for the ssh_key_reuse_probe adapter and tool layer. The
subprocess call is mocked; the private key is never real key material.
"""
from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

from tradecraft.adapters.ssh_key_reuse_probe import execute as reuse_execute
from tradecraft.adapters.ssh_key_reuse_probe import parse as reuse_parse
from tradecraft.tools.ssh_key_reuse_probe import SshKeyReuseProbe
from tradecraft.tools.profiles import load_profile

FAKE_PEM = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n"


def _proc(returncode=0, stdout="", stderr=""):
    p = MagicMock()
    p.returncode = returncode
    p.stdout = stdout
    p.stderr = stderr
    return p


# ---------------------------------------------------------------------------
# execute.py helpers
# ---------------------------------------------------------------------------


def test_is_private_key_pem_accepts_real_header():
    assert reuse_execute.is_private_key_pem(FAKE_PEM) is True
    assert reuse_execute.is_private_key_pem("not a key") is False
    assert reuse_execute.is_private_key_pem("") is False


def test_parse_target_host_and_port():
    assert reuse_execute.parse_target("10.0.0.1") == ("10.0.0.1", None)
    assert reuse_execute.parse_target("10.0.0.1:2222") == ("10.0.0.1", 2222)
    assert reuse_execute.parse_target("10.0.0.1:not-a-port") == ("", None)
    assert reuse_execute.parse_target("") == ("", None)
    assert reuse_execute.parse_target("host:99999") == ("", None)  # out of range


def test_build_argv_contains_batch_mode_and_no_password_fallback():
    argv = reuse_execute.build_argv("10.0.0.1", 2222, "svc", "/tmp/fakekey")
    assert argv[0] == "ssh"
    assert "-i" in argv and argv[argv.index("-i") + 1] == "/tmp/fakekey"
    assert "-p" in argv and argv[argv.index("-p") + 1] == "2222"
    assert "BatchMode=yes" in argv
    assert "PasswordAuthentication=no" in argv
    assert argv[-2] == "svc@10.0.0.1"
    assert argv[-1] == reuse_execute.CONFIRM_COMMAND


def test_private_key_file_is_0600_and_removed_after_use():
    import os

    captured_path = None
    with reuse_execute.private_key_file(FAKE_PEM) as path:
        captured_path = path
        assert os.path.isfile(path)
        mode = os.stat(path).st_mode & 0o777
        assert mode == 0o600
        with open(path) as fh:
            assert fh.read() == FAKE_PEM
    assert not os.path.exists(captured_path)


# ---------------------------------------------------------------------------
# execute(): validation
# ---------------------------------------------------------------------------


def test_execute_requires_user_and_nonempty_targets():
    assert reuse_execute.execute(FAKE_PEM, "", ["10.0.0.1"]).error == "ssh_user is required for ssh_key_reuse_probe"
    assert "non-empty list" in reuse_execute.execute(FAKE_PEM, "svc", []).error


def test_execute_rejects_more_than_max_targets():
    targets = [f"10.0.0.{i}" for i in range(reuse_execute.MAX_TARGETS + 1)]
    raw = reuse_execute.execute(FAKE_PEM, "svc", targets)
    assert "maximum per call" in raw.error
    assert raw.targets_requested == len(targets)


def test_execute_rejects_non_pem_key():
    raw = reuse_execute.execute("not a key", "svc", ["10.0.0.1"])
    assert "must be PEM private key content" in raw.error


def test_execute_rejects_malformed_target():
    raw = reuse_execute.execute(FAKE_PEM, "svc", ["not:a:valid:target"])
    assert "invalid target" in raw.error


def test_execute_missing_binary():
    with patch("tradecraft.adapters.ssh_key_reuse_probe.execute.find_ssh_binary", return_value=None):
        raw = reuse_execute.execute(FAKE_PEM, "svc", ["10.0.0.1"])
    assert raw.error == "ssh binary not found on PATH"


def test_execute_deduplicates_same_host_port():
    runner = MagicMock(return_value=_proc(returncode=255))
    with patch("tradecraft.adapters.ssh_key_reuse_probe.execute.find_ssh_binary", return_value="/usr/bin/ssh"):
        raw = reuse_execute.execute(FAKE_PEM, "svc", ["10.0.0.1:22", "10.0.0.1:22"], runner=runner)
    assert raw.error is None
    assert len(raw.attempts) == 1
    assert runner.call_count == 1


# ---------------------------------------------------------------------------
# execute(): per-target outcomes
# ---------------------------------------------------------------------------


def test_execute_runs_one_attempt_per_target_in_order():
    runner = MagicMock(
        side_effect=[
            _proc(returncode=255, stderr="Permission denied (publickey)."),
            _proc(returncode=0, stdout="uid=1000(svc) gid=1000(svc)\n"),
        ]
    )
    with patch("tradecraft.adapters.ssh_key_reuse_probe.execute.find_ssh_binary", return_value="/usr/bin/ssh"):
        raw = reuse_execute.execute(FAKE_PEM, "svc", ["10.0.0.1", "10.0.0.2"], runner=runner)

    assert raw.error is None
    assert runner.call_count == 2
    assert [a.host for a in raw.attempts] == ["10.0.0.1", "10.0.0.2"]
    assert raw.attempts[0].returncode == 255
    assert raw.attempts[1].returncode == 0


def test_execute_timeout_is_per_target_error_not_fatal():
    runner = MagicMock(
        side_effect=[
            subprocess.TimeoutExpired(cmd="ssh", timeout=30),
            _proc(returncode=0, stdout="uid=0(root)\n"),
        ]
    )
    with patch("tradecraft.adapters.ssh_key_reuse_probe.execute.find_ssh_binary", return_value="/usr/bin/ssh"):
        raw = reuse_execute.execute(FAKE_PEM, "svc", ["10.0.0.1", "10.0.0.2"], runner=runner)
    assert raw.attempts[0].error == "ssh timed out after 30s"
    assert raw.attempts[1].returncode == 0


# ---------------------------------------------------------------------------
# parse.py
# ---------------------------------------------------------------------------


def test_parse_target_result_auth_failure_255():
    attempt = reuse_execute.RawTargetAttempt(
        target="10.0.0.1", host="10.0.0.1", port=None, returncode=255,
        stderr="Permission denied (publickey).",
    )
    out = reuse_parse.parse_target_result(attempt)
    assert out["auth_succeeded"] is False
    assert out["confirmation_output_present"] is False
    assert "Permission denied" in out["error"]


def test_parse_target_result_success_with_shell():
    attempt = reuse_execute.RawTargetAttempt(
        target="10.0.0.1", host="10.0.0.1", port=22, returncode=0,
        stdout="uid=1000(svc) gid=1000(svc)\n",
    )
    out = reuse_parse.parse_target_result(attempt)
    assert out["auth_succeeded"] is True
    assert out["confirmation_output_present"] is True
    assert out["confirmation_output"] == "uid=1000(svc) gid=1000(svc)"


def test_parse_target_result_success_but_restricted_session():
    # Auth succeeded (non-255 exit) but the forced/command session produced
    # no output -- e.g. a restricted shell or a command= in authorized_keys.
    attempt = reuse_execute.RawTargetAttempt(
        target="10.0.0.1", host="10.0.0.1", port=22, returncode=0, stdout="", stderr="",
    )
    out = reuse_parse.parse_target_result(attempt)
    assert out["auth_succeeded"] is True
    assert out["confirmation_output_present"] is False
    assert "confirmation_output" not in out


def test_parse_target_result_adapter_level_error_passthrough():
    attempt = reuse_execute.RawTargetAttempt(target="10.0.0.1", host="10.0.0.1", error="ssh timed out after 30s")
    out = reuse_parse.parse_target_result(attempt)
    assert out["auth_succeeded"] is False
    assert out["error"] == "ssh timed out after 30s"


def test_parse_key_reuse_result_summarizes_multiple_targets():
    raw = reuse_execute.RawKeyReuseResult(
        ssh_user="svc",
        targets_requested=2,
        attempts=[
            reuse_execute.RawTargetAttempt(target="10.0.0.1", host="10.0.0.1", returncode=255, stderr="Permission denied"),
            reuse_execute.RawTargetAttempt(target="10.0.0.2", host="10.0.0.2", returncode=0, stdout="uid=0(root)\n"),
        ],
    )
    out = reuse_parse.parse_key_reuse_result(raw)
    assert out["targets_attempted"] == 2
    assert out["auth_succeeded_count"] == 1
    assert out["confirmed_shell_count"] == 1
    assert len(out["results"]) == 2


def test_parse_key_reuse_result_error_passthrough():
    raw = reuse_execute.RawKeyReuseResult(ssh_user="svc", targets_requested=3, error="targets has too many entries")
    out = reuse_parse.parse_key_reuse_result(raw)
    assert out["error"] == "targets has too many entries"
    assert out["results"] == []


# ---------------------------------------------------------------------------
# Tool glue
# ---------------------------------------------------------------------------


def test_tool_run_end_to_end_and_facts():
    tool = SshKeyReuseProbe()
    assert tool.tool_id == "ssh_key_reuse_probe"
    assert tool.destructive is False
    assert tool.required_binary == "ssh"

    with patch("tradecraft.adapters.ssh_key_reuse_probe.execute.find_ssh_binary", return_value="/usr/bin/ssh"), \
            patch(
                "tradecraft.adapters.ssh_key_reuse_probe.execute.subprocess.run",
                side_effect=[_proc(returncode=255), _proc(returncode=0, stdout="uid=0(root)\n")],
            ):
        result = tool.run(private_key=FAKE_PEM, ssh_user="svc", targets=["10.0.0.1", "10.0.0.2:2222"])

    assert result["auth_succeeded_count"] == 1
    assert result["confirmed_shell_count"] == 1

    facts = tool.extract_facts({}, result)
    assert len(facts) == 2
    assert facts[0] == {
        "host": "10.0.0.1", "port": 22, "protocol": "ssh",
        "ssh_key_reuse_auth_succeeded": False, "ssh_key_reuse_shell_confirmed": False,
    }
    assert facts[1] == {
        "host": "10.0.0.2", "port": 2222, "protocol": "ssh",
        "ssh_key_reuse_auth_succeeded": True, "ssh_key_reuse_shell_confirmed": True,
    }
    # The private key must never appear in the result or facts.
    import json
    assert FAKE_PEM not in json.dumps(result)
    assert FAKE_PEM not in json.dumps(facts)


def test_tool_facts_empty_on_adapter_error():
    tool = SshKeyReuseProbe()
    result = {"error": "targets has too many entries", "results": []}
    assert tool.extract_facts({}, result) == []


def test_tool_extract_evidence_returns_none_without_a_target_param():
    # scope_param is null and there is no singular target/host/url/domain/ip
    # parameter (only the plural "targets"), so the base default finds no
    # target string to key evidence off of.
    tool = SshKeyReuseProbe()
    result = {"auth_succeeded_count": 1, "results": [{"host": "10.0.0.1"}]}
    assert tool.extract_evidence({"targets": ["10.0.0.1"]}, result) is None


def test_profile_assignment():
    post_tools = load_profile("post-exploitation")
    web_tools = load_profile("web")
    assert "ssh_key_reuse_probe" in post_tools
    assert "ssh_key_reuse_probe" not in web_tools
