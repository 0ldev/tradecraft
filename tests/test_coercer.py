from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

from tradecraft.adapters.coercer import execute as coercer_execute
from tradecraft.adapters.coercer import parse as coercer_parse
from tradecraft.tools.coercer import Coercer


def test_build_argv():
    argv = coercer_execute.build_argv(
        target="192.168.1.10",
        domain="corp.local",
        username="user1",
        password="Password123!",
    )
    assert argv[0] == "coercer"
    assert argv[1] == "scan"
    assert "-t" in argv
    assert argv[argv.index("-t") + 1] == "192.168.1.10"
    assert "-d" in argv
    assert argv[argv.index("-d") + 1] == "corp.local"
    assert "-u" in argv
    assert argv[argv.index("-u") + 1] == "user1"
    assert "-p" in argv
    assert argv[argv.index("-p") + 1] == "Password123!"


def test_execute_empty_target():
    res = coercer_execute.execute("")
    assert res.error == "empty target host"


def test_execute_missing_binary():
    with patch("tradecraft.adapters.coercer.execute.find_binary", return_value=None):
        res = coercer_execute.execute("192.168.1.10")
        assert res.error == "coercer executable not found on PATH"


def test_execute_success():
    with patch("tradecraft.adapters.coercer.execute.find_binary", return_value="/usr/local/bin/coercer"):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout="[+] Vulnerable to PetitPotam (MS-EFSR)\n[+] Vulnerable to PrinterBug (MS-RPRN)",
                stderr="",
            )
            res = coercer_execute.execute("dc01.corp.local")
            assert res.error is None
            assert "PetitPotam" in res.stdout


def test_parse_coercer_output():
    raw = coercer_execute.RawCoercerResult(
        target="dc01.corp.local",
        stdout="[+] Target is vulnerable to MS-EFSR (PetitPotam) via \\pipe\\efsrpc\n",
    )
    parsed = coercer_parse.parse_coercer_output(raw)
    assert parsed["vulnerable"] is True
    assert "MS-EFSR" in parsed["coercible_methods"] or "PetitPotam" in parsed["coercible_methods"]


def test_tool_glue():
    tool = Coercer()
    assert tool.tool_id == "coercer"
    assert tool.required_binary == "coercer"

    with patch("tradecraft.adapters.coercer.execute.find_binary", return_value="/usr/local/bin/coercer"):
        assert tool.is_available() is True

    with patch("tradecraft.adapters.coercer.execute.find_binary", return_value=None):
        assert tool.is_available() is False


def test_tool_run_and_facts():
    tool = Coercer()
    with patch("tradecraft.adapters.coercer.execute.find_binary", return_value="/usr/local/bin/coercer"):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout="[+] Vulnerable to MS-RPRN (PrinterBug)",
                stderr="",
            )
            res = tool.run(target="192.168.1.5")
            assert res["vulnerable"] is True

            facts = tool.extract_facts({"target": "192.168.1.5"}, res)
            assert len(facts) == 1
            assert facts[0]["host"] == "192.168.1.5"
            assert facts[0]["coercion_vulnerable"] is True
