from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

from tradecraft.adapters.kerbrute_spray import execute as spray_execute
from tradecraft.adapters.kerbrute_spray import parse as spray_parse
from tradecraft.tools.kerbrute_spray import KerbruteSpray


def test_build_argv():
    argv = spray_execute.build_argv(
        domain="corp.local",
        password="Spring2026!",
        wordlist_path="/path/to/users.txt",
        dc_ip="10.0.0.1",
    )
    assert argv[0] == "kerbrute"
    assert argv[1] == "passwordspray"
    assert "-d" in argv
    assert argv[argv.index("-d") + 1] == "corp.local"
    assert "--dc" in argv
    assert argv[argv.index("--dc") + 1] == "10.0.0.1"
    assert argv[-2] == "/path/to/users.txt"
    assert argv[-1] == "Spring2026!"


def test_execute_empty_domain_or_password():
    assert spray_execute.execute("", "pass").error == "empty domain"
    assert spray_execute.execute("corp.local", "").error == "single password is required for kerbrute_spray"


def test_execute_multiple_passwords_rejected():
    res = spray_execute.execute("corp.local", "pass1\npass2")
    assert res.error is not None
    assert "single password" in res.error


def test_execute_success():
    with patch("tradecraft.adapters.kerbrute_spray.execute.find_binary", return_value="/usr/local/bin/kerbrute"):
        with patch("os.path.isfile", return_value=True):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = subprocess.CompletedProcess(
                    args=[],
                    returncode=0,
                    stdout="[+] VALID LOGIN:  admin@corp.local : Spring2026!\n",
                    stderr="",
                )
                res = spray_execute.execute("corp.local", "Spring2026!")
                assert res.error is None
                assert "VALID LOGIN" in res.stdout


def test_parse_kerbrute_spray_output():
    raw = spray_execute.RawKerbruteSprayResult(
        domain="corp.local",
        password="Spring2026!",
        stdout=(
            "[*] Starting password spray...\n"
            "[+] VALID LOGIN:  svc_backup@corp.local : Spring2026!\n"
            "[+] VALID LOGIN:  jdoe@corp.local : Spring2026!\n"
        ),
    )
    parsed = spray_parse.parse_kerbrute_spray_output(raw)
    assert parsed["total_valid"] == 2
    assert "svc_backup@corp.local" in parsed["valid_credentials"]
    assert "jdoe@corp.local" in parsed["valid_credentials"]


def test_tool_glue():
    tool = KerbruteSpray()
    assert tool.tool_id == "kerbrute_spray"
    assert tool.required_binary == "kerbrute"
    assert tool.destructive is True

    with patch("tradecraft.adapters.kerbrute_spray.execute.find_binary", return_value="/usr/local/bin/kerbrute"):
        assert tool.is_available() is True


def test_tool_run_and_facts():
    tool = KerbruteSpray()
    with patch("tradecraft.adapters.kerbrute_spray.execute.find_binary", return_value="/usr/local/bin/kerbrute"):
        with patch("os.path.isfile", return_value=True):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = subprocess.CompletedProcess(
                    args=[],
                    returncode=0,
                    stdout="[+] VALID LOGIN:  admin@corp.local : Winter2026!\n",
                    stderr="",
                )
                res = tool.run(domain="corp.local", password="Winter2026!")
                assert res["total_valid"] == 1
                assert "admin@corp.local" in res["valid_credentials"]

                facts = tool.extract_facts({"domain": "corp.local"}, res)
                assert len(facts) == 1
                assert facts[0]["host"] == "corp.local"
                assert facts[0]["port"] == 88
                assert facts[0]["valid_credentials_found"] is True
