from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

from tradecraft.adapters.jwt_tool import execute as jt_execute
from tradecraft.adapters.jwt_tool import parse as jt_parse
from tradecraft.tools.jwt_tool import JwtTool

SAMPLE_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)


def test_build_argv_with_target():
    argv = jt_execute.build_argv(
        script_path="/opt/jwt_tool/jwt_tool.py",
        token=SAMPLE_JWT,
        target_url="https://api.example.com/me",
        header_name="Authorization",
        header_prefix="Bearer ",
        canary_claim="admin=true",
    )
    assert argv[0] == "python3"
    assert argv[1] == "/opt/jwt_tool/jwt_tool.py"
    assert argv[2] == SAMPLE_JWT
    assert "-t" in argv
    assert argv[argv.index("-t") + 1] == "https://api.example.com/me"
    assert "-rh" in argv
    assert f"Authorization: Bearer {SAMPLE_JWT}" in argv[argv.index("-rh") + 1]
    assert "-M" in argv
    assert argv[argv.index("-M") + 1] == "at"
    assert "-pc" in argv
    assert argv[argv.index("-pc") + 1] == "admin=true"


def test_execute_invalid_token():
    res = jt_execute.execute("not_a_valid_jwt")
    assert res.error is not None
    assert "invalid JWT format" in res.error


def test_execute_missing_script():
    with patch("tradecraft.adapters.jwt_tool.execute.find_script", return_value=None):
        res = jt_execute.execute(SAMPLE_JWT)
        assert res.error is not None
        assert "jwt_tool not found" in res.error


def test_execute_success():
    with patch("tradecraft.adapters.jwt_tool.execute.find_script", return_value="/opt/jwt_tool/jwt_tool.py"):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout="[+] Test: Alg: none accepted - Status: 200 OK\neyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.\n",
                stderr="",
            )
            res = jt_execute.execute(SAMPLE_JWT, target_url="https://api.example.com")
            assert res.error is None
            assert res.returncode == 0
            assert "Status: 200 OK" in res.stdout


def test_parse_jwt_tool_output():
    raw = jt_execute.RawJwtToolResult(
        token=SAMPLE_JWT,
        target_url="https://api.example.com",
        stdout=(
            "[*] Starting Playbook Tests...\n"
            "[+] Found: Alg: none bypass - Status: 200 OK\n"
            "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.\n"
        ),
    )
    parsed = jt_parse.parse_jwt_tool_output(raw)
    assert parsed["vulnerable"] is True
    assert parsed["total_findings"] >= 1
    assert len(parsed["forged_tokens"]) == 1
    assert parsed["forged_tokens"][0] == "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0."


def test_tool_availability():
    tool = JwtTool()
    assert tool.tool_id == "jwt_tool"
    assert tool.required_binary == "python3"

    with patch("tradecraft.adapters.jwt_tool.execute.find_script", return_value="/opt/jwt_tool/jwt_tool.py"):
        assert tool.is_available() is True

    with patch("tradecraft.adapters.jwt_tool.execute.find_script", return_value=None):
        assert tool.is_available() is False


def test_tool_run_and_evidence():
    tool = JwtTool()
    with patch("tradecraft.adapters.jwt_tool.execute.find_script", return_value="/opt/jwt_tool/jwt_tool.py"):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout="[+] Vulnerable to alg:none - Status: 200\neyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0.\n",
                stderr="",
            )
            result = tool.run(token=SAMPLE_JWT, target_url="https://target.corp/api")
            assert result["vulnerable"] is True
            assert "_full_evidence" in result

            ev_host, ev_data = tool.extract_evidence({"target_url": "https://target.corp/api"}, result)
            assert ev_host == "target.corp"
            assert "forged_tokens" in ev_data

            facts = tool.extract_facts({"target_url": "https://target.corp/api"}, result)
            assert len(facts) == 1
            assert facts[0]["host"] == "target.corp"
            assert facts[0]["port"] == 443
            assert facts[0]["jwt_vulnerable"] is True
