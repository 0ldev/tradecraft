import subprocess
from unittest.mock import patch

from tradecraft.adapters.tplmap.execute import (
    SCRIPT_PATH,
    RawTplmapResult,
    execute,
    find_script,
)
from tradecraft.adapters.tplmap.parse import parse_detection


def test_parse_detection_not_vulnerable():
    stdout = """
[*] Version: 1.4.0
[*] Scanning url: http://example.com/?name=test
[*] Testing if Query parameter 'name' is injectable
[-] Tested parameters appear to be not injectable.
"""
    parsed = parse_detection(stdout)
    assert parsed["vulnerable"] is False
    assert "not injectable" in parsed["raw_output"]
    assert "engine" not in parsed


def test_parse_detection_vulnerable():
    stdout = """
[+] Jinja2 plugin has confirmed injection with tag '*' 
[+] SSTImap identified the following injection point:

  Query parameter: name
  Engine: Jinja2
  Injection: *
  Context: text
  OS: posix-linux
  Technique: rendered
  Capabilities:

    Shell command execution: ok
"""
    parsed = parse_detection(stdout)
    assert parsed["vulnerable"] is True
    assert parsed["engine"] == "Jinja2"
    assert parsed["parameter"] == "name"
    assert parsed["technique"] == "rendered"


def test_execute_script_not_found():
    with patch("tradecraft.adapters.tplmap.execute.find_script", return_value=None):
        res = execute("http://example.com/?q=1")
        assert res.error is not None
        assert f"tplmap not found at {SCRIPT_PATH}" in res.error


def test_execute_calls_detection_mode_only():
    with patch("tradecraft.adapters.tplmap.execute.find_script", return_value="/opt/tplmap/tplmap.py"):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[], returncode=0, stdout="detection output", stderr=""
            )
            res = execute("http://example.com/?q=test", timeout=120)

            mock_run.assert_called_once()
            called_cmd = mock_run.call_args[0][0]
            assert called_cmd[0] == "python3"
            assert called_cmd[1] == "/opt/tplmap/tplmap.py"
            assert "-u" in called_cmd
            assert called_cmd[called_cmd.index("-u") + 1] == "http://example.com/?q=test"
            # Verify strictly NO exploitation flags
            assert "--os-cmd" not in called_cmd
            assert "--os-shell" not in called_cmd
            assert res.stdout == "detection output"
            assert res.error is None


def test_execute_timeout():
    with patch("tradecraft.adapters.tplmap.execute.find_script", return_value="/opt/tplmap/tplmap.py"):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="tplmap", timeout=5)):
            res = execute("http://example.com/?q=test", timeout=5)
            assert res.error == "tplmap execution timed out"
