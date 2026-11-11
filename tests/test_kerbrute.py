"""
Unit tests for kerbrute adapter and tool layer.
"""
from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

from tradecraft.adapters.kerbrute import execute as kb_execute
from tradecraft.adapters.kerbrute import parse as kb_parse
from tradecraft.tools.kerbrute import Kerbrute
from tradecraft.tools.profiles import load_profile


def test_normalize_target_host():
    assert kb_parse.normalize_target_host("10.0.0.1") == "10.0.0.1"
    assert kb_parse.normalize_target_host("ldap://dc01.corp.local:389") == "dc01.corp.local"
    assert kb_parse.normalize_target_host("10.0.0.1:88") == "10.0.0.1"
    assert kb_parse.normalize_target_host("   ") == ""


def test_parse_host_port():
    assert kb_parse.parse_host_port("10.0.0.1") == ("10.0.0.1", 88)
    assert kb_parse.parse_host_port("10.0.0.1:8888") == ("10.0.0.1", 8888)
    assert kb_parse.parse_host_port("ldap://dc01.corp.local:389") == ("dc01.corp.local", 389)


def test_build_argv():
    argv = kb_execute.build_argv("10.0.0.1", "corp.local", "/tmp/users.txt", safe=True)
    assert "userenum" in argv
    assert "--dc" in argv
    assert "10.0.0.1" in argv
    assert "-d" in argv
    assert "corp.local" in argv
    assert "--safe" in argv
    assert "/tmp/users.txt" in argv


def test_parse_kerbrute_output():
    stdout_sample = r"""
    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - Ronnie Flathers @ropnop

2026/11/03 14:00:00 >  [+] VALID USERNAME:       admin@corp.local
2026/11/03 14:00:01 >  [+] VALID USERNAME:       administrator@corp.local
2026/11/03 14:00:02 >  [+] VALID USERNAME:       ADMIN@CORP.LOCAL
2026/11/03 14:00:03 >  Done! Executed 30 queries in 0.420s
    """
    users = kb_parse.parse_kerbrute_output(stdout_sample)
    assert len(users) == 2
    assert "admin@corp.local" in users
    assert "administrator@corp.local" in users


def test_execute_with_mock_runner(tmp_path):
    mock_runner = MagicMock()
    proc = MagicMock()
    proc.returncode = 0
    proc.stdout = "2026/11/03 > [+] VALID USERNAME: jdoe@corp.local\n"
    proc.stderr = ""
    mock_runner.return_value = proc

    with patch("tradecraft.adapters.kerbrute.execute.find_kerbrute_binary", return_value="/usr/local/bin/kerbrute"):
        res = kb_execute.execute(
            target="10.0.0.1",
            domain="corp.local",
            runner=mock_runner,
        )

    assert res.error is None
    assert res.usernames == ["jdoe@corp.local"]
    assert mock_runner.called

    # No wordlist given: falls back to the persistent bundled default
    # list under config/wordlists/, not a per-run temp file.
    call_argv = mock_runner.call_args[0][0]
    wordlist_arg = call_argv[-1]
    assert wordlist_arg.endswith("config/wordlists/kerbrute-usernames.txt")
    assert os.path.isfile(wordlist_arg)


def test_execute_missing_domain():
    res = kb_execute.execute("10.0.0.1", domain="")
    assert res.error == "missing required Active Directory domain"


def test_tool_run_and_facts():
    tool = Kerbrute()
    assert tool.tool_id == "kerbrute"
    assert tool.destructive is False

    with patch("tradecraft.adapters.kerbrute.execute.execute") as mock_exec:
        mock_raw = kb_parse.RawKerbruteResult(
            target="10.0.0.1",
            domain="corp.local",
            usernames=["admin@corp.local", "svc_sql@corp.local"],
            stdout="valid users",
        )
        mock_exec.return_value = mock_raw

        result = tool.run(target="10.0.0.1", domain="corp.local")
        assert result["total_users_found"] == 2
        assert result["usernames"] == ["admin@corp.local", "svc_sql@corp.local"]

        evidence = tool.extract_evidence({"target": "10.0.0.1"}, result)
        assert evidence is not None
        host, full = evidence
        assert host == "10.0.0.1"
        assert full["total_users_found"] == 2

        facts = tool.extract_facts({"target": "10.0.0.1"}, result)
        assert len(facts) == 1
        assert facts[0]["host"] == "10.0.0.1"
        assert facts[0]["port"] == 88
        assert facts[0]["ad_domain"] == "corp.local"
        assert facts[0]["ad_valid_usernames_count"] == 2


def test_profile_assignment():
    ad_tools = load_profile("ad-network")
    web_tools = load_profile("web")

    assert "kerbrute" in ad_tools
    assert "kerbrute" not in web_tools
