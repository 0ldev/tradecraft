from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

from tradecraft.adapters.smuggler import execute as smuggler_execute
from tradecraft.adapters.smuggler import parse as smuggler_parse
from tradecraft.tools.smuggler import Smuggler


def test_build_argv():
    argv = smuggler_execute.build_argv(
        script_path="/opt/smuggler/smuggler.py",
        target_url="https://example.com/",
        timeout=10,
    )
    assert argv[0] == "python3"
    assert argv[1] == "/opt/smuggler/smuggler.py"
    assert "-u" in argv
    assert argv[argv.index("-u") + 1] == "https://example.com/"
    assert "-q" in argv
    assert "-t" in argv
    assert argv[argv.index("-t") + 1] == "10"


def test_execute_empty_target():
    res = smuggler_execute.execute("")
    assert res.error == "empty target URL"


def test_execute_missing_script():
    with patch("tradecraft.adapters.smuggler.execute.find_script", return_value=None):
        res = smuggler_execute.execute("https://example.com")
        assert res.error is not None
        assert "smuggler script not found" in res.error


def test_execute_success():
    with patch("tradecraft.adapters.smuggler.execute.find_script", return_value="/opt/smuggler/smuggler.py"):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout="[CRITICAL] Found CL.TE potential desync on endpoint /",
                stderr="",
            )
            res = smuggler_execute.execute("https://example.com")
            assert res.error is None
            assert "CL.TE" in res.stdout


def test_parse_smuggler_output_vulnerable():
    raw = smuggler_execute.RawSmugglerResult(
        target_url="https://example.com/",
        stdout=(
            "[*] Testing mutations for https://example.com/ ...\n"
            "[CRITICAL] Confirmed TE.CL desync vulnerability!\n"
            "Server timeout triggered on chunked mutation\n"
        ),
    )
    parsed = smuggler_parse.parse_smuggler_output(raw)
    assert parsed["vulnerable"] is True
    assert "TE.CL" in parsed["desync_types"]
    assert len(parsed["findings"]) >= 1


def test_parse_smuggler_output_clean():
    raw = smuggler_execute.RawSmugglerResult(
        target_url="https://example.com/",
        stdout="[*] All 40 mutations tested. No desync detected.\n",
    )
    parsed = smuggler_parse.parse_smuggler_output(raw)
    assert parsed["vulnerable"] is False
    assert parsed["desync_types"] == []
    assert parsed["findings"] == []


def test_tool_glue():
    tool = Smuggler()
    assert tool.tool_id == "smuggler"
    assert tool.required_binary == "python3"

    with patch("tradecraft.adapters.smuggler.execute.find_script", return_value="/opt/smuggler/smuggler.py"):
        assert tool.is_available() is True

    with patch("tradecraft.adapters.smuggler.execute.find_script", return_value=None):
        assert tool.is_available() is False


def test_tool_run_and_facts():
    tool = Smuggler()
    with patch("tradecraft.adapters.smuggler.execute.find_script", return_value="/opt/smuggler/smuggler.py"):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout="[CRITICAL] Confirmed CL.TE desync vulnerability!",
                stderr="",
            )
            res = tool.run(target="https://target.corp/")
            assert res["vulnerable"] is True
            assert "CL.TE" in res["desync_types"]

            facts = tool.extract_facts({"target": "https://target.corp/"}, res)
            assert len(facts) == 1
            assert facts[0]["host"] == "target.corp"
            assert facts[0]["port"] == 443
            assert facts[0]["http_smuggling_vulnerable"] is True
            assert "CL.TE" in facts[0]["desync_types"]
