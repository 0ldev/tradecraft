"""A subprocess killed at its timeout keeps whatever it wrote before the kill,
and the tool result says the run was cut short. A timeout must never look
like a clean run."""
from __future__ import annotations

import json
import subprocess
from unittest.mock import patch

from tradecraft.adapters.nuclei import execute as nuclei_execute
from tradecraft.adapters.partial_output import captured_text, from_timeout
from tradecraft.tools.dalfox import Dalfox
from tradecraft.tools.nuclei import Nuclei

FINDING = json.dumps({
    "template-id": "tech-detect",
    "info": {"name": "Tech Detect", "severity": "info"},
    "matched-at": "https://example.com/",
    "type": "http",
})


def _timeout(stdout=b"", stderr=b"") -> subprocess.TimeoutExpired:
    return subprocess.TimeoutExpired(cmd=["x"], timeout=180, output=stdout, stderr=stderr)


def test_captured_text_decodes_bytes_and_handles_none():
    assert captured_text(b"abc\xff") == "abc�"
    assert captured_text(None) == ""
    assert captured_text("plain") == "plain"


def test_from_timeout_returns_partial_stdout_and_stderr():
    out, err = from_timeout(_timeout(stdout=b"line1\n", stderr=b"warn"))
    assert out == "line1\n"
    assert err == "warn"


def test_nuclei_adapter_keeps_partial_output_on_timeout():
    with patch("shutil.which", return_value="/usr/bin/nuclei"), patch(
        "subprocess.run", side_effect=_timeout(stdout=(FINDING + "\n").encode())
    ):
        raw = nuclei_execute.execute("https://example.com", overall_timeout=180)
    assert raw.timed_out is True
    assert raw.timeout_seconds == 180
    assert FINDING in raw.stdout
    assert raw.error == "nuclei timed out after 180s"


def test_nuclei_tool_reports_partial_findings_as_timed_out_not_clean():
    with patch("shutil.which", return_value="/usr/bin/nuclei"), patch(
        "subprocess.run", side_effect=_timeout(stdout=(FINDING + "\n").encode())
    ):
        res = Nuclei().run(target="https://example.com")
    assert res["timed_out"] is True
    assert res["total_findings"] == 1
    assert "error" not in res
    assert "timeout_note" in res
    assert "not mean the target is clean" in res["timeout_note"]


def test_nuclei_tool_reports_error_when_nothing_was_captured():
    with patch("shutil.which", return_value="/usr/bin/nuclei"), patch(
        "subprocess.run", side_effect=_timeout()
    ):
        res = Nuclei().run(target="https://example.com")
    assert res["timed_out"] is True
    assert res["error"] == "nuclei timed out after 180s"


def test_nuclei_normal_completion_has_no_timeout_fields():
    proc = subprocess.CompletedProcess([], 0, stdout=FINDING + "\n", stderr="")
    with patch("shutil.which", return_value="/usr/bin/nuclei"), patch(
        "subprocess.run", return_value=proc
    ):
        res = Nuclei().run(target="https://example.com")
    assert "timed_out" not in res
    assert "timeout_note" not in res


def test_dalfox_adapter_keeps_partial_stdout_on_timeout():
    progress = "[*] scanning parameter q\n"
    with patch("shutil.which", return_value="/usr/bin/dalfox"), patch(
        "subprocess.run", side_effect=_timeout(stdout=progress.encode())
    ):
        from tradecraft.adapters.dalfox import execute as dalfox_execute

        raw = dalfox_execute.execute("https://example.com/?q=1", subprocess_timeout=45)
    assert raw.timed_out is True
    assert raw.timeout_seconds == 45
    assert "scanning parameter" in raw.stdout


def test_dalfox_timeout_is_not_recorded_as_xss_tested():
    tool = Dalfox()
    with patch("shutil.which", return_value="/usr/bin/dalfox"), patch(
        "subprocess.run", side_effect=_timeout(stdout=b"[*] scanning\n")
    ):
        res = tool.run(target="https://example.com/?q=1", parameter="q")
    assert res["timed_out"] is True
    assert "timeout_note" in res
    facts = tool.extract_facts({"target": "https://example.com/?q=1"}, res)
    assert all("xss_tested" not in f for f in facts)
