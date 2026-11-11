from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

from tradecraft.adapters.ghauri import execute as ghauri_execute
from tradecraft.adapters.ghauri import parse as ghauri_parse
from tradecraft.tools.ghauri import Ghauri


def test_build_argv_basic():
    argv = ghauri_execute.build_argv(
        target_url="https://example.com/item.php?id=1",
        parameter="id",
        level=1,
    )
    assert argv[0] == "ghauri"
    assert "-u" in argv
    assert argv[argv.index("-u") + 1] == "https://example.com/item.php?id=1"
    assert "-p" in argv
    assert argv[argv.index("-p") + 1] == "id"
    assert "--level" in argv
    assert argv[argv.index("--level") + 1] == "1"
    assert "--batch" in argv
    assert "--current-user" in argv


def test_execute_empty_target():
    res = ghauri_execute.execute("")
    assert res.error == "empty target URL"


def test_execute_missing_binary():
    with patch("tradecraft.adapters.ghauri.execute.find_binary", return_value=None):
        res = ghauri_execute.execute("https://example.com")
        assert res.error == "ghauri executable not found on PATH"


def test_execute_success():
    with patch("tradecraft.adapters.ghauri.execute.find_binary", return_value="/usr/local/bin/ghauri"):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout="GET parameter 'id' is vulnerable. back-end DBMS: MySQL >= 5.6 current user: 'root@localhost'",
                stderr="",
            )
            res = ghauri_execute.execute("https://example.com/item?id=1", parameter="id")
            assert res.error is None
            assert "is vulnerable" in res.stdout


def test_parse_ghauri_output_vulnerable():
    raw = ghauri_execute.RawGhauriResult(
        target_url="https://example.com/item?id=1",
        parameter="id",
        stdout=(
            "--- Testing parameter 'id' ---\n"
            "GET parameter 'id' appears to be dynamic\n"
            "GET parameter 'id' is vulnerable.\n"
            "Title: boolean-based blind - Parameter: id\n"
            "back-end DBMS: PostgreSQL\n"
            "current user: 'postgres'\n"
        ),
    )
    parsed = ghauri_parse.parse_ghauri_output(raw)
    assert parsed["vulnerable"] is True
    assert parsed["dbms"] == "PostgreSQL"
    assert parsed["current_user"] == "postgres"
    assert "boolean-based blind" in parsed["techniques"]


def test_parse_ghauri_output_clean():
    raw = ghauri_execute.RawGhauriResult(
        target_url="https://example.com/item?id=1",
        parameter="id",
        stdout="all tested parameters appear to be not injectable.",
    )
    parsed = ghauri_parse.parse_ghauri_output(raw)
    assert parsed["vulnerable"] is False
    assert parsed["dbms"] == ""
    assert parsed["techniques"] == []


def test_tool_glue():
    tool = Ghauri()
    assert tool.tool_id == "ghauri"
    assert tool.required_binary == "ghauri"

    with patch("tradecraft.adapters.ghauri.execute.find_binary", return_value="/usr/local/bin/ghauri"):
        assert tool.is_available() is True

    with patch("tradecraft.adapters.ghauri.execute.find_binary", return_value=None):
        assert tool.is_available() is False


def test_tool_run_and_facts():
    tool = Ghauri()
    with patch("tradecraft.adapters.ghauri.execute.find_binary", return_value="/usr/local/bin/ghauri"):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout="GET parameter 'id' is vulnerable. back-end DBMS: MySQL >= 8.0",
                stderr="",
            )
            res = tool.run(target="https://target.com/view?id=10", parameter="id")
            assert res["vulnerable"] is True
            assert res["dbms"] == "MySQL >= 8.0"

            facts = tool.extract_facts({"target": "https://target.com/view?id=10"}, res)
            assert len(facts) == 1
            assert facts[0]["host"] == "target.com"
            assert facts[0]["sqli_vulnerable"] is True
            assert facts[0]["dbms"] == "MySQL >= 8.0"
