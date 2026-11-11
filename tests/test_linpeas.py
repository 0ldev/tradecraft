"""
Unit tests for the linpeas adapter, parser, Tool wrapper, and contract.

linpeas is invoked over SSH on a host already reached via some other
foothold (sshpass + ssh + `curl ... linpeas.sh | sh`), so this suite is
unit/argv-level only. The SUID/SGID "--->" marker and the Vulnerable-label
CVE negation fixtures below reproduce linpeas's real output shape,
confirmed against an actual linpeas.sh run in an isolated container.
"""
from __future__ import annotations

import subprocess
from unittest.mock import MagicMock

from tradecraft.adapters.linpeas import execute as lp_execute
from tradecraft.adapters.linpeas import parse as lp_parse
from tradecraft.tools.linpeas import Linpeas
from tradecraft.tools.profiles import load_profile

# linpeas flags a genuinely exploitable SUID binary with a literal
# "--->" marker; a CVE check always prints "Vulnerable to CVE-XXXX ....
# Yes/No" regardless of the answer, so only "Yes" counts.
SAMPLE_LINPEAS_OUTPUT = """
\x1b[1;4mLEGEND\x1b[0m:

╔══════════╣ SUID - Check easy privesc, exploits and write perms
-rwsr-xr-x 1 root root 85K Feb  6  2024 /bin/mount
-rwsr-xr-x 1 root root 27K Jan 10  2023 /usr/bin/base64 --->  GTFOBins: base64
-rwsr-xr-x 1 root root 55K Jan 10  2023 /usr/bin/find

╔══════════╣ Kernel Exploit Enumeration
Vulnerable to CVE-2016-5195 (DirtyCow) .............. No
Vulnerable to CVE-2021-3156 (Sudo Baron Samedit) .............. Yes

╔══════════╣ Interesting Software / Files
pkg: openssl-1.1.1 (Vulnerable to CVE-2022-0778) .............. Yes
"""

# BSD `pkg audit`'s own section title ("Vulnerable Packages", printed
# bare -- not one of linpeas's own "╔═...╣" box headers), distinct from
# a real finding; the parser must not treat the title line itself as a
# vector.
SAMPLE_PKG_AUDIT_SECTION = """
Vulnerable Packages
pkg: libxml2-2.9.10 is vulnerable: CVE-2022-40303
"""

# A failed ssh/sshpass connection never produces linpeas output at all.
SAMPLE_SSH_ERROR_STDOUT = ""
SAMPLE_SSH_ERROR_STDERR = (
    "ssh: connect to host 10.0.0.15 port 22: Connection refused\n"
)


def test_strip_ansi():
    raw = "\x1b[31;1mRED TEXT\x1b[0m normal \x1b[32mGREEN\x1b[0m"
    assert lp_parse.strip_ansi(raw) == "RED TEXT normal GREEN"


def test_parse_host_port_default():
    assert lp_parse.parse_host_port("10.0.0.15") == ("10.0.0.15", None)


def test_parse_host_port_explicit():
    assert lp_parse.parse_host_port("10.0.0.15:2222") == ("10.0.0.15", 2222)


def test_parse_host_port_empty():
    assert lp_parse.parse_host_port("") == ("", None)


def test_parse_host_port_non_numeric_suffix_kept_whole():
    # Only a genuinely numeric suffix is treated as a port -- anything
    # else is passed through untouched rather than mis-split.
    assert lp_parse.parse_host_port("fe80::1") == ("fe80::1", None)


def test_normalize_target_host():
    assert lp_parse.normalize_target_host("10.0.0.15:2222") == "10.0.0.15"
    assert lp_parse.normalize_target_host("10.0.0.15") == "10.0.0.15"


def test_parse_linpeas_findings_suid_marker():
    findings = lp_parse.parse_linpeas_findings(SAMPLE_LINPEAS_OUTPUT)
    suid_findings = [f for f in findings if "SUID/SGID" in f]
    assert len(suid_findings) == 1
    assert "base64" in suid_findings[0]
    assert "--->" in suid_findings[0]


def test_parse_linpeas_findings_cve_negation():
    findings = lp_parse.parse_linpeas_findings(SAMPLE_LINPEAS_OUTPUT)
    cve_findings = [f for f in findings if "CVE vector" in f]
    # CVE-2016-5195 prints "No" and must be excluded; CVE-2021-3156 and
    # CVE-2022-0778 both print "Yes" and must be included.
    joined = "\n".join(cve_findings)
    assert "CVE-2016-5195" not in joined
    assert "CVE-2021-3156" in joined
    assert "CVE-2022-0778" in joined
    assert len(cve_findings) == 2


def test_parse_linpeas_findings_excludes_pkg_audit_section_title():
    findings = lp_parse.parse_linpeas_findings(SAMPLE_PKG_AUDIT_SECTION)
    assert not any(f == "Vulnerable Packages" for f in findings)
    # The actual vulnerable-package line itself has no "Vulnerable"
    # substring in this real pkg-audit format, so nothing is found here
    # either -- this fixture exists only to pin the title-exclusion.
    assert findings == []


def test_parse_linpeas_findings_caps_count_not_actual_parsing():
    # Many SUID markers in one run.
    output = "\n".join(f"/bin/tool{i} ---> GTFOBins: tool{i}" for i in range(250))
    findings = lp_parse.parse_linpeas_findings(output)
    assert len(findings) == 250  # the raw parser itself is uncapped


def test_detect_ssh_error():
    err = lp_parse.detect_ssh_error(SAMPLE_SSH_ERROR_STDOUT, SAMPLE_SSH_ERROR_STDERR)
    assert err is not None
    assert "connection refused" in err.lower()


def test_detect_ssh_error_none_when_clean():
    assert lp_parse.detect_ssh_error(SAMPLE_LINPEAS_OUTPUT, "") is None


def test_parse_linpeas_result_success():
    raw = lp_parse.RawLinpeasResult(
        target="10.0.0.15", stdout=SAMPLE_LINPEAS_OUTPUT, returncode=0
    )
    result = lp_parse.parse_linpeas_result(raw)
    assert result["status"] == "success"
    assert result["target"] == "10.0.0.15"
    assert result["finding_count"] == 3
    assert result["findings_truncated"] is False
    assert result.get("error") is None


def test_parse_linpeas_result_execution_error():
    raw = lp_parse.RawLinpeasResult(
        target="10.0.0.15", error="sshpass binary not found on PATH"
    )
    result = lp_parse.parse_linpeas_result(raw)
    assert result["status"] == "failed"
    assert "sshpass" in result["error"]


def test_parse_linpeas_result_ssh_failure_with_empty_output():
    raw = lp_parse.RawLinpeasResult(
        target="10.0.0.15",
        stdout=SAMPLE_SSH_ERROR_STDOUT,
        stderr=SAMPLE_SSH_ERROR_STDERR,
        returncode=255,
    )
    result = lp_parse.parse_linpeas_result(raw)
    assert result["status"] == "failed"
    assert "connection refused" in result["error"].lower()


def test_parse_linpeas_result_caps_findings():
    output = "\n".join(f"/bin/tool{i} ---> GTFOBins: tool{i}" for i in range(250))
    raw = lp_parse.RawLinpeasResult(target="10.0.0.15", stdout=output, returncode=0)
    result = lp_parse.parse_linpeas_result(raw)
    assert result["status"] == "success"
    assert result["finding_count"] == 250
    assert len(result["findings"]) == lp_parse.MAX_FINDINGS_RETURNED
    assert result["findings_truncated"] is True


def test_build_argv_default_port():
    argv = lp_execute.build_argv(
        target="10.0.0.15", ssh_user="alice", ssh_pass="s3cr3t", binary="sshpass"
    )
    assert argv == [
        "sshpass",
        "-p",
        "s3cr3t",
        "ssh",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "alice@10.0.0.15",
        lp_execute.REMOTE_CMD,
    ]
    assert "linpeas.sh | sh" in argv[-1]


def test_build_argv_explicit_port():
    argv = lp_execute.build_argv(
        target="10.0.0.15:2222",
        ssh_user="alice",
        ssh_pass="s3cr3t",
        binary="sshpass",
    )
    assert "-p" in argv
    # Both sshpass's own "-p <password>" and ssh's "-p <port>" are
    # present; the port one must carry the target's explicit port.
    assert argv.count("-p") == 2
    assert "2222" in argv
    assert "alice@10.0.0.15" in argv


def test_execute_empty_target():
    res = lp_execute.execute(target="", ssh_user="alice", ssh_pass="s3cr3t")
    assert "empty target" in res.error.lower()


def test_execute_missing_ssh_user():
    res = lp_execute.execute(target="10.0.0.15", ssh_user="", ssh_pass="s3cr3t")
    assert "ssh_user" in res.error


def test_execute_missing_ssh_pass():
    res = lp_execute.execute(target="10.0.0.15", ssh_user="alice", ssh_pass="")
    assert "ssh_pass" in res.error


def test_execute_missing_binary(monkeypatch):
    monkeypatch.setattr(lp_execute, "find_sshpass_binary", lambda: None)
    res = lp_execute.execute(target="10.0.0.15", ssh_user="alice", ssh_pass="s3cr3t")
    assert "sshpass" in res.error
    assert "not found on path" in res.error.lower()


def test_execute_timeout(monkeypatch):
    monkeypatch.setattr(
        lp_execute, "find_sshpass_binary", lambda: "/usr/bin/sshpass"
    )

    def mock_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=5)

    res = lp_execute.execute(
        target="10.0.0.15", ssh_user="alice", ssh_pass="s3cr3t", runner=mock_run
    )
    assert "timed out" in res.error.lower()


def test_execute_success_with_binary_patched(monkeypatch):
    monkeypatch.setattr(
        lp_execute, "find_sshpass_binary", lambda: "/usr/bin/sshpass"
    )
    mock_proc = MagicMock()
    mock_proc.stdout = SAMPLE_LINPEAS_OUTPUT
    mock_proc.stderr = ""
    mock_proc.returncode = 0

    res = lp_execute.execute(
        target="10.0.0.15",
        ssh_user="alice",
        ssh_pass="s3cr3t",
        runner=lambda *a, **kw: mock_proc,
    )
    assert res.error is None
    assert res.returncode == 0
    assert "Sudo Baron Samedit" in res.stdout


def test_linpeas_tool_wrapper(monkeypatch):
    tool = Linpeas()
    assert tool.tool_id == "linpeas"
    assert tool.destructive is False
    assert tool.required_binary == "sshpass"

    monkeypatch.setattr(
        lp_execute, "find_sshpass_binary", lambda: "/usr/bin/sshpass"
    )
    mock_proc = MagicMock()
    mock_proc.stdout = SAMPLE_LINPEAS_OUTPUT
    mock_proc.stderr = ""
    mock_proc.returncode = 0
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: mock_proc)

    result = tool.run(target="10.0.0.15", ssh_user="alice", ssh_pass="s3cr3t")
    assert result["status"] == "success"
    assert result["finding_count"] == 3
    assert "_full_evidence" in result

    evidence = tool.extract_evidence({"target": "10.0.0.15"}, result)
    assert evidence is not None
    host, full_data = evidence
    assert host == "10.0.0.15"
    assert "Sudo Baron Samedit" in full_data["raw_stdout"]
    assert "_full_evidence" not in result  # popped by extract_evidence

    result["evidence_id"] = "linpeas:10.0.0.15"
    facts = tool.extract_facts({"target": "10.0.0.15"}, result)
    assert len(facts) == 1
    fact = facts[0]
    assert fact["host"] == "10.0.0.15"
    assert fact["port"] == 22
    assert fact["protocol"] == "ssh"
    assert fact["linpeas_enumerated"] is True
    assert fact["linpeas_finding_count"] == 3
    assert fact["evidence"] == "linpeas:10.0.0.15"


def test_linpeas_tool_wrapper_explicit_port(monkeypatch):
    tool = Linpeas()
    monkeypatch.setattr(
        lp_execute, "find_sshpass_binary", lambda: "/usr/bin/sshpass"
    )
    mock_proc = MagicMock()
    mock_proc.stdout = SAMPLE_LINPEAS_OUTPUT
    mock_proc.stderr = ""
    mock_proc.returncode = 0
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: mock_proc)

    result = tool.run(target="10.0.0.15:2222", ssh_user="alice", ssh_pass="s3cr3t")
    facts = tool.extract_facts({"target": "10.0.0.15:2222"}, result)
    assert facts[0]["host"] == "10.0.0.15"
    assert facts[0]["port"] == 2222


def test_linpeas_tool_failure_has_no_facts(monkeypatch):
    tool = Linpeas()
    monkeypatch.setattr(
        lp_execute, "find_sshpass_binary", lambda: "/usr/bin/sshpass"
    )
    mock_proc = MagicMock()
    mock_proc.stdout = SAMPLE_SSH_ERROR_STDOUT
    mock_proc.stderr = SAMPLE_SSH_ERROR_STDERR
    mock_proc.returncode = 255
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: mock_proc)

    result = tool.run(target="10.0.0.15", ssh_user="alice", ssh_pass="wrong")
    assert result["status"] == "failed"
    assert tool.extract_facts({"target": "10.0.0.15"}, result) == []
    # The transcript is still useful evidence of what was attempted.
    assert tool.extract_evidence({"target": "10.0.0.15"}, result) is not None


def test_linpeas_tool_is_available(monkeypatch):
    tool = Linpeas()
    monkeypatch.setattr(
        lp_execute, "find_sshpass_binary", lambda: "/usr/bin/sshpass"
    )
    assert tool.is_available() is True

    monkeypatch.setattr(lp_execute, "find_sshpass_binary", lambda: None)
    assert tool.is_available() is False


def test_linpeas_profile_membership():
    assert "linpeas" in load_profile("post-exploitation")
    # linpeas is deliberately NOT in ad-network or kubernetes directly --
    # it is not AD/k8s-specific, and is shared via the smaller
    # post-exploitation profile instead.
    assert "linpeas" not in load_profile("ad-network")
