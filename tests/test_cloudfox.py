from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

from tradecraft.adapters.cloudfox import execute as cf_execute
from tradecraft.adapters.cloudfox import parse as cf_parse
from tradecraft.tools.cloudfox import Cloudfox


def test_build_argv():
    argv = cf_execute.build_argv(
        provider="aws",
        command="permissions",
        out_dir="/tmp/test",
    )
    assert argv[0] == "cloudfox"
    assert argv[1] == "aws"
    assert argv[2] == "permissions"
    assert "-o" in argv
    assert argv[argv.index("-o") + 1] == "/tmp/test"


def test_execute_unsupported_provider():
    res = cf_execute.execute(provider="oracle")
    assert res.error is not None
    assert "unsupported cloud provider" in res.error


def test_execute_missing_binary():
    with patch("tradecraft.adapters.cloudfox.execute.find_binary", return_value=None):
        res = cf_execute.execute(provider="aws")
        assert res.error == "cloudfox executable not found on PATH"


def test_execute_success():
    with patch("tradecraft.adapters.cloudfox.execute.find_binary", return_value="/usr/local/bin/cloudfox"):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout="[+] Found 2 IAM users with AdministratorAccess\n[*] IMDSv1 instances: 1",
                stderr="",
            )
            res = cf_execute.execute(provider="aws", command="permissions")
            assert res.error is None
            assert res.provider == "aws"
            assert "AdministratorAccess" in res.stdout


def test_parse_cloudfox_output():
    raw = cf_execute.RawCloudfoxResult(
        provider="aws",
        command="permissions",
        stdout="[!] Privilege Escalation path found via iam:PassRole to ec2.amazonaws.com\n",
        json_data=[{"user": "dev", "privesc": True}],
    )
    parsed = cf_parse.parse_cloudfox_output(raw)
    assert parsed["findings_count"] >= 1
    assert parsed["findings"][0]["user"] == "dev"


def test_tool_glue():
    tool = Cloudfox()
    assert tool.tool_id == "cloudfox"
    assert tool.required_binary == "cloudfox"

    with patch("tradecraft.adapters.cloudfox.execute.find_binary", return_value="/usr/local/bin/cloudfox"):
        assert tool.is_available() is True

    with patch("tradecraft.adapters.cloudfox.execute.find_binary", return_value=None):
        assert tool.is_available() is False


def test_tool_run_and_facts():
    tool = Cloudfox()
    with patch("tradecraft.adapters.cloudfox.execute.find_binary", return_value="/usr/local/bin/cloudfox"):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout="[!] Privilege Escalation path found",
                stderr="",
            )
            res = tool.run(provider="aws", target="123456789012")
            assert res["findings_count"] >= 1

            facts = tool.extract_facts({"target": "123456789012"}, res)
            assert len(facts) == 1
            assert facts[0]["host"] == "123456789012"
            assert facts[0]["cloud_attack_paths_found"] is True
