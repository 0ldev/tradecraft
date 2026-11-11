from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

from tradecraft.adapters.cewl import execute as cewl_execute
from tradecraft.adapters.cewl import parse as cewl_parse
from tradecraft.tools.cewl import Cewl


def test_build_argv():
    argv = cewl_execute.build_argv("https://target.local", depth=3, min_word_length=4, output_file="/tmp/out.txt")
    assert argv[0] == "cewl"
    assert argv[argv.index("-d") + 1] == "3"
    assert argv[argv.index("-m") + 1] == "4"
    assert argv[argv.index("-w") + 1] == "/tmp/out.txt"
    assert argv[-1] == "https://target.local"


def test_execute_empty_target():
    assert cewl_execute.execute("").error == "empty target"


def test_execute_adds_default_scheme():
    with patch("shutil.which", return_value="/usr/bin/cewl"):
        with patch("subprocess.run") as mock_run:
            def fake_run(argv, **kwargs):
                Path(argv[argv.index("-w") + 1]).write_text("acme\nwidget\nfoobar\n")
                return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
            mock_run.side_effect = fake_run

            res = cewl_execute.execute("target.local")
            assert mock_run.call_args[0][0][-1] == "https://target.local"
            assert res.words == ["acme", "widget", "foobar"]
            assert res.error is None


def test_execute_binary_not_found():
    with patch("shutil.which", return_value=None):
        res = cewl_execute.execute("https://target.local")
        assert res.error == "cewl executable not found on PATH"


def test_execute_clamps_depth_and_max_words():
    with patch("shutil.which", return_value="/usr/bin/cewl"):
        with patch("subprocess.run") as mock_run:
            def fake_run(argv, **kwargs):
                assert argv[argv.index("-d") + 1] == str(cewl_execute.MAX_DEPTH)
                Path(argv[argv.index("-w") + 1]).write_text("\n".join(f"word{i}" for i in range(300)))
                return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
            mock_run.side_effect = fake_run

            res = cewl_execute.execute("https://target.local", depth=99, max_words=99999)
            assert len(res.words) == cewl_execute.MAX_WORDS


def test_execute_timeout():
    with patch("shutil.which", return_value="/usr/bin/cewl"):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="cewl", timeout=5)):
            res = cewl_execute.execute("https://target.local", timeout=5)
            assert "timed out" in res.error


def test_execute_no_output_file_reports_error():
    with patch("shutil.which", return_value="/usr/bin/cewl"):
        with patch("subprocess.run", return_value=subprocess.CompletedProcess([], 1, stdout="", stderr="connection refused")):
            res = cewl_execute.execute("https://target.local")
            assert "no output file" in res.error
            assert "connection refused" in res.error


def test_parse_cewl_result_success():
    raw = cewl_execute.RawCewlResult(words=["acme", "widget"])
    parsed = cewl_parse.parse_cewl_result(raw, "https://target.local")
    assert parsed == {"target": "https://target.local", "words": ["acme", "widget"], "total_words": 2}


def test_parse_cewl_result_error():
    raw = cewl_execute.RawCewlResult(error="cewl executable not found on PATH")
    parsed = cewl_parse.parse_cewl_result(raw, "https://target.local")
    assert parsed["error"] == "cewl executable not found on PATH"
    assert parsed["words"] == []


def test_tool_run_wires_through(tmp_path):
    with patch("shutil.which", return_value="/usr/bin/cewl"):
        with patch("subprocess.run") as mock_run:
            def fake_run(argv, **kwargs):
                Path(argv[argv.index("-w") + 1]).write_text("acme\n")
                return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")
            mock_run.side_effect = fake_run

            result = Cewl().run(target="https://target.local")
            assert result["words"] == ["acme"]
            assert result["total_words"] == 1
