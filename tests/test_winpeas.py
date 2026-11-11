"""
Unit tests for the winpeas adapter, parser, Tool wrapper, and contract.

winpeas runs winPEASany.exe remotely via Impacket's wmiexec.py against
an already-credentialed Windows/AD host, so this suite is unit/argv-level
only. The marker fixtures below reproduce winPEASany.exe's real output
markers, verified against real PEASS-ng releases.
"""
from __future__ import annotations

import subprocess
from unittest.mock import MagicMock

from tradecraft.adapters.winpeas import execute as wp_execute
from tradecraft.adapters.winpeas import parse as wp_parse
from tradecraft.tools.profiles import load_profile
from tradecraft.tools.winpeas import Winpeas

# Modern winPEASany.exe releases mark critical findings with '[!]'; the
# keyword fallback catches findings or inline text without an explicit
# marker.
SAMPLE_WINPEAS_OUTPUT = """
\x1b[1;4mLEGEND\x1b[0m:

[!] Unquoted Service Path
    Service: VulnSvc
    Path: C:\\Program Files\\Vendor\\service.exe

[!] Modifiable Service Binary
    Service: Another Service
    Path: C:\\Services\\app.exe
    Permissions: Everyone [AllAccess]

[!] SeImpersonatePrivilege is enabled
    User: NT SERVICE\\MSSQLSERVER

(!CHECK!) AlwaysInstallElevated is enabled
"""

# A legacy-style release relying on the keyword fallback alone, with no
# explicit '[!]'/'(!)' marker on the Unquoted Service Path line.
SAMPLE_LEGACY_OUTPUT = """
Found: Unquoted Service Path in LegacySvc
"""

SAMPLE_AUTH_FAILURE_OUTPUT = (
    "[-] SMB SessionError: STATUS_LOGON_FAILURE(The attempted logon is "
    "invalid due to a bad username or authentication information.)\n"
)


def test_strip_ansi():
    raw = "\x1b[31;1mRED\x1b[0m normal \x1b[34mBLUE\x1b[0m"
    assert wp_parse.strip_ansi(raw) == "RED normal BLUE"


def test_normalize_target_host_bare():
    assert wp_parse.normalize_target_host("10.0.0.20") == "10.0.0.20"


def test_normalize_target_host_strips_port():
    assert wp_parse.normalize_target_host("10.0.0.20:445") == "10.0.0.20"


def test_normalize_target_host_strips_scheme():
    assert wp_parse.normalize_target_host("https://dc01.corp.local") == "dc01.corp.local"


def test_normalize_target_host_empty():
    assert wp_parse.normalize_target_host("") == ""


def test_parse_winpeas_findings_explicit_markers():
    findings = wp_parse.parse_winpeas_findings(SAMPLE_WINPEAS_OUTPUT)
    joined = "\n".join(findings)
    assert "Unquoted Service Path" in joined
    assert "Modifiable Service Binary" in joined
    assert "SeImpersonatePrivilege is enabled" in joined
    assert "AlwaysInstallElevated is enabled" in joined
    # Each finding line is reported on its own.
    assert len(findings) == 4


def test_parse_winpeas_findings_keyword_fallback():
    findings = wp_parse.parse_winpeas_findings(SAMPLE_LEGACY_OUTPUT)
    assert len(findings) == 1
    assert "Unquoted Service Path" in findings[0]


def test_parse_winpeas_findings_strips_ansi_first():
    output = "\x1b[31m[!] SeAssignPrimaryToken enabled\x1b[0m"
    findings = wp_parse.parse_winpeas_findings(output)
    assert findings == ["Potential privilege escalation vector: [!] SeAssignPrimaryToken enabled"]


def test_parse_winpeas_findings_empty_lines_skipped():
    assert wp_parse.parse_winpeas_findings("\n\n   \n") == []


def test_detect_auth_failure_logon_failure():
    err = wp_parse.detect_auth_failure(SAMPLE_AUTH_FAILURE_OUTPUT, "")
    assert err is not None
    assert "STATUS_LOGON_FAILURE" in err


def test_detect_auth_failure_access_denied():
    err = wp_parse.detect_auth_failure("", "STATUS_ACCESS_DENIED")
    assert err is not None
    assert "STATUS_ACCESS_DENIED" in err


def test_detect_auth_failure_traceback_and_exception():
    output = (
        "Traceback (most recent call last):\n"
        '  File "wmiexec.py", line 42, in <module>\n'
        "Exception: Connection error"
    )
    err = wp_parse.detect_auth_failure(output, "")
    assert err is not None
    assert "Exception: Connection error" in err


def test_detect_auth_failure_none_when_clean():
    assert wp_parse.detect_auth_failure(SAMPLE_WINPEAS_OUTPUT, "") is None


def test_parse_winpeas_result_success():
    raw = wp_parse.RawWinpeasResult(
        target="10.0.0.20",
        domain="corp.local",
        stdout=SAMPLE_WINPEAS_OUTPUT,
        returncode=0,
    )
    result = wp_parse.parse_winpeas_result(raw)
    assert result["status"] == "success"
    assert result["target"] == "10.0.0.20"
    assert result["domain"] == "corp.local"
    assert result["finding_count"] == 4
    assert result["findings_truncated"] is False
    assert result.get("error") is None


def test_parse_winpeas_result_execution_error():
    raw = wp_parse.RawWinpeasResult(
        target="10.0.0.20", domain="corp.local", error="wmiexec.py binary not found on PATH"
    )
    result = wp_parse.parse_winpeas_result(raw)
    assert result["status"] == "failed"
    assert "wmiexec.py" in result["error"]


def test_parse_winpeas_result_auth_failure():
    raw = wp_parse.RawWinpeasResult(
        target="10.0.0.20",
        domain="corp.local",
        stdout=SAMPLE_AUTH_FAILURE_OUTPUT,
        returncode=1,
    )
    result = wp_parse.parse_winpeas_result(raw)
    assert result["status"] == "failed"
    assert "STATUS_LOGON_FAILURE" in result["error"]


def test_parse_winpeas_result_caps_findings():
    output = "\n".join(f"[!] finding number {i}" for i in range(250))
    raw = wp_parse.RawWinpeasResult(
        target="10.0.0.20", domain="corp.local", stdout=output, returncode=0
    )
    result = wp_parse.parse_winpeas_result(raw)
    assert result["status"] == "success"
    assert result["finding_count"] == 250
    assert len(result["findings"]) == wp_parse.MAX_FINDINGS_RETURNED
    assert result["findings_truncated"] is True


def test_build_argv_password():
    argv = wp_execute.build_argv(
        target="10.0.0.20",
        domain="corp.local",
        username="alice",
        password="Password123!",
        binary="wmiexec.py",
    )
    assert argv == [
        "wmiexec.py",
        "-dc-ip",
        "10.0.0.20",
        "corp.local/alice:Password123!@10.0.0.20",
        wp_execute.REMOTE_CMD,
    ]
    assert "winPEASany.exe" in argv[-1]
    assert "Remove-Item" in argv[-1]


def test_build_argv_hashes_bare_nt():
    argv = wp_execute.build_argv(
        target="10.0.0.20",
        domain="corp.local",
        username="alice",
        hashes="31d6cfe0d16ae931b73c59d7e0c089c0",
        binary="wmiexec.py",
    )
    assert argv[0] == "wmiexec.py"
    assert argv[1] == "-hashes"
    assert argv[2] == ":31d6cfe0d16ae931b73c59d7e0c089c0"
    assert "-dc-ip" in argv
    assert "corp.local/alice@10.0.0.20" in argv


def test_build_argv_hashes_lm_nt_passthrough():
    argv = wp_execute.build_argv(
        target="10.0.0.20",
        domain="corp.local",
        username="alice",
        hashes="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
        binary="wmiexec.py",
    )
    assert argv[2] == "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"


def test_execute_empty_target():
    res = wp_execute.execute(target="", domain="corp.local", username="alice", password="x")
    assert "empty target" in res.error.lower()


def test_execute_missing_domain():
    res = wp_execute.execute(target="10.0.0.20", domain="", username="alice", password="x")
    assert "domain" in res.error


def test_execute_missing_username():
    res = wp_execute.execute(target="10.0.0.20", domain="corp.local", username="", password="x")
    assert "username" in res.error


def test_execute_missing_secret():
    res = wp_execute.execute(target="10.0.0.20", domain="corp.local", username="alice")
    assert "password or hashes" in res.error


def test_execute_rejects_password_and_hashes_together():
    res = wp_execute.execute(
        target="10.0.0.20",
        domain="corp.local",
        username="alice",
        password="x",
        hashes="y",
    )
    assert "not both" in res.error


def test_execute_missing_binary(monkeypatch):
    monkeypatch.setattr(wp_execute, "find_wmiexec_binary", lambda: None)
    res = wp_execute.execute(
        target="10.0.0.20", domain="corp.local", username="alice", password="x"
    )
    assert "wmiexec.py" in res.error
    assert "not found on path" in res.error.lower()


def test_execute_timeout(monkeypatch):
    monkeypatch.setattr(wp_execute, "find_wmiexec_binary", lambda: "/usr/local/bin/wmiexec.py")

    def mock_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=5)

    res = wp_execute.execute(
        target="10.0.0.20",
        domain="corp.local",
        username="alice",
        password="x",
        runner=mock_run,
    )
    assert "timed out" in res.error.lower()


def test_execute_success_with_mock_runner(monkeypatch):
    monkeypatch.setattr(wp_execute, "find_wmiexec_binary", lambda: "/usr/local/bin/wmiexec.py")
    mock_proc = MagicMock()
    mock_proc.stdout = SAMPLE_WINPEAS_OUTPUT
    mock_proc.stderr = ""
    mock_proc.returncode = 0

    res = wp_execute.execute(
        target="10.0.0.20",
        domain="corp.local",
        username="alice",
        password="Password123!",
        runner=lambda *a, **kw: mock_proc,
    )
    assert res.error is None
    assert res.returncode == 0
    assert "SeImpersonatePrivilege" in res.stdout


def test_winpeas_tool_wrapper(monkeypatch):
    tool = Winpeas()
    assert tool.tool_id == "winpeas"
    assert tool.destructive is False
    assert tool.required_binary == "wmiexec.py"

    monkeypatch.setattr(wp_execute, "find_wmiexec_binary", lambda: "/usr/local/bin/wmiexec.py")
    mock_proc = MagicMock()
    mock_proc.stdout = SAMPLE_WINPEAS_OUTPUT
    mock_proc.stderr = ""
    mock_proc.returncode = 0
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: mock_proc)

    result = tool.run(
        target="10.0.0.20", domain="corp.local", username="alice", password="Password123!"
    )
    assert result["status"] == "success"
    assert result["finding_count"] == 4
    assert "_full_evidence" in result

    evidence = tool.extract_evidence({"target": "10.0.0.20"}, result)
    assert evidence is not None
    host, full_data = evidence
    assert host == "10.0.0.20"
    assert "SeImpersonatePrivilege" in full_data["raw_stdout"]
    assert "_full_evidence" not in result

    result["evidence_id"] = "winpeas:10.0.0.20"
    facts = tool.extract_facts({"target": "10.0.0.20"}, result)
    assert len(facts) == 1
    fact = facts[0]
    assert fact["host"] == "10.0.0.20"
    assert fact["port"] == 135
    assert fact["protocol"] == "wmi"
    assert fact["winpeas_enumerated"] is True
    assert fact["winpeas_finding_count"] == 4
    assert fact["evidence"] == "winpeas:10.0.0.20"


def test_winpeas_tool_failure_has_no_facts(monkeypatch):
    tool = Winpeas()
    monkeypatch.setattr(wp_execute, "find_wmiexec_binary", lambda: "/usr/local/bin/wmiexec.py")
    mock_proc = MagicMock()
    mock_proc.stdout = SAMPLE_AUTH_FAILURE_OUTPUT
    mock_proc.stderr = ""
    mock_proc.returncode = 1
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: mock_proc)

    result = tool.run(
        target="10.0.0.20", domain="corp.local", username="alice", password="wrong"
    )
    assert result["status"] == "failed"
    assert tool.extract_facts({"target": "10.0.0.20"}, result) == []
    # The transcript is still useful evidence of what was attempted.
    assert tool.extract_evidence({"target": "10.0.0.20"}, result) is not None


def test_winpeas_tool_is_available(monkeypatch):
    tool = Winpeas()
    monkeypatch.setattr(wp_execute, "find_wmiexec_binary", lambda: "/usr/local/bin/wmiexec.py")
    assert tool.is_available() is True

    monkeypatch.setattr(wp_execute, "find_wmiexec_binary", lambda: None)
    assert tool.is_available() is False


def test_winpeas_profile_membership():
    assert "winpeas" in load_profile("post-exploitation")
    assert "winpeas" in load_profile("ad-network")
