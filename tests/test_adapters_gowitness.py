import subprocess
from pathlib import Path
from unittest.mock import patch

from tradecraft.adapters.gowitness import execute as gowitness_execute
from tradecraft.adapters.gowitness.execute import build_argv, execute, RawGowitnessResult


def test_build_argv_structure():
    argv = build_argv("https://example.com/login", "/tmp/screens", timeout=15, delay=2)
    assert argv[0] == "gowitness"
    assert argv[1:3] == ["scan", "single"]
    assert "-u" in argv
    assert argv[argv.index("-u") + 1] == "https://example.com/login"
    assert "-s" in argv
    assert argv[argv.index("-s") + 1] == "/tmp/screens"
    assert "--screenshot-format" in argv
    assert argv[argv.index("--screenshot-format") + 1] == "png"
    assert "--write-none" in argv
    assert "--delay" in argv
    assert argv[argv.index("--delay") + 1] == "2"
    assert "-T" in argv
    assert argv[argv.index("-T") + 1] == "15"


def test_execute_empty_target():
    res = execute("   ")
    assert res.error == "empty target"
    assert res.png_bytes == b""


def test_execute_success_creates_and_reads_png():
    fake_png_bytes = b"\x89PNG\r\n\x1a\nfakeimagebytes"

    def fake_subprocess_run(cmd, **kwargs):
        # cmd: [... "-s", screenshot_path, ...]
        s_idx = cmd.index("-s")
        screenshot_dir = Path(cmd[s_idx + 1])
        (screenshot_dir / "example_com.png").write_bytes(fake_png_bytes)
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    with patch("subprocess.run", side_effect=fake_subprocess_run):
        res = execute("https://example.com")
        assert res.error is None
        assert res.png_bytes == fake_png_bytes
        assert res.final_url == "https://example.com"


def test_execute_no_png_file_captured():
    def fake_subprocess_run(cmd, **kwargs):
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=0,
            stdout="",
            stderr="ERRO failed to witness target target=https://example.com err='net::ERR_NAME_NOT_RESOLVED'",
        )

    with patch("subprocess.run", side_effect=fake_subprocess_run):
        res = execute("https://example.com")
        assert res.png_bytes == b""
        assert "ERR_NAME_NOT_RESOLVED" in res.error


def test_execute_binary_not_found():
    with patch("subprocess.run", side_effect=FileNotFoundError):
        res = execute("https://example.com")
        assert res.error == "gowitness executable not found"
        assert res.png_bytes == b""


def test_execute_timeout_expired():
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="gowitness", timeout=10)):
        res = execute("https://example.com", timeout=10)
        assert "timed out after 10s" in res.error
        assert res.png_bytes == b""
