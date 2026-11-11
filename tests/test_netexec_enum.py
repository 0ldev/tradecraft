"""
Unit tests for the netexec_enum adapter, parser, Tool wrapper, and
contract.

Fixtures are real captured output from NetExec 1.5.1 on CT 115
(`netexec smb 192.168.15.23 -u "" -p "" <flags>` against a Samba host on
the operator's own lab network), not hand-typed shapes -- the previous
draft of this adapter's fixtures matched a parser that did not match real
NetExec output, so every captured section below is kept verbatim.
"""
from __future__ import annotations

import base64
import subprocess
from unittest.mock import MagicMock

from tradecraft.adapters.netexec_enum import execute as nxe_execute
from tradecraft.adapters.netexec_enum import parse as nxe_parse
from tradecraft.tools.netexec_enum import NetexecEnum
from tradecraft.tools.profiles import load_profile

# Real capture: netexec smb 192.168.15.23 -u "" -p "" --shares
SAMPLE_SMB_SHARES = """\
SMB                      192.168.15.23   445    JELLYFIN         [*] Unix - Samba (name:JELLYFIN) (domain:tail3f8bbe.ts.net) (signing:False) (SMBv1:False) (Null Auth:True)
SMB                      192.168.15.23   445    JELLYFIN         [+] tail3f8bbe.ts.net\\:
SMB                      192.168.15.23   445    JELLYFIN         [*] Enumerated shares
SMB                      192.168.15.23   445    JELLYFIN         Share           Permissions            Remark
SMB                      192.168.15.23   445    JELLYFIN         -----           -----------            ------
SMB                      192.168.15.23   445    JELLYFIN         print$                                 Printer Drivers
SMB                      192.168.15.23   445    JELLYFIN         media
SMB                      192.168.15.23   445    JELLYFIN         IPC$                                   IPC Service (Samba 4.17.12-Debian)
"""

# Real capture: netexec smb 192.168.15.23 -u "" -p "" --users
SAMPLE_SMB_USERS = """\
SMB                      192.168.15.23   445    JELLYFIN         [*] Unix - Samba (name:JELLYFIN) (domain:tail3f8bbe.ts.net) (signing:False) (SMBv1:False) (Null Auth:True)
SMB                      192.168.15.23   445    JELLYFIN         [+] tail3f8bbe.ts.net\\:
SMB                      192.168.15.23   445    JELLYFIN         -Username-                    -Last PW Set-       -BadPW- -Description-
SMB                      192.168.15.23   445    JELLYFIN         nasuser                       2026-09-15 17:23:38 0
SMB                      192.168.15.23   445    JELLYFIN         [*] Enumerated 1 local users: JELLYFIN
"""

# Real capture: netexec smb 192.168.15.23 -u "" -p "" --pass-pol
SAMPLE_SMB_PASS_POL = """\
SMB                      192.168.15.23   445    JELLYFIN         [*] Unix - Samba (name:JELLYFIN) (domain:tail3f8bbe.ts.net) (signing:False) (SMBv1:False) (Null Auth:True)
SMB                      192.168.15.23   445    JELLYFIN         [+] tail3f8bbe.ts.net\\:
SMB                      192.168.15.23   445    JELLYFIN         [+] Dumping password info for domain: JELLYFIN
SMB                      192.168.15.23   445    JELLYFIN         Minimum password length: 5
SMB                      192.168.15.23   445    JELLYFIN         Password history length: None
SMB                      192.168.15.23   445    JELLYFIN         Maximum password age: 37 days 6 hours 21 minutes
SMB                      192.168.15.23   445    JELLYFIN         Password Complexity Flags: 000000
SMB                      192.168.15.23   445    JELLYFIN         Account Lockout Threshold: None
SMB                      192.168.15.23   445    JELLYFIN         Forced Log off Time: 37 days 6 hours 21 minutes
"""

# Real capture: netexec smb 192.168.15.23 -u "" -p "" --disks
SAMPLE_SMB_DISKS = """\
SMB                      192.168.15.23   445    JELLYFIN         [*] Unix - Samba (name:JELLYFIN) (domain:tail3f8bbe.ts.net) (signing:False) (SMBv1:False) (Null Auth:True)
SMB                      192.168.15.23   445    JELLYFIN         [+] tail3f8bbe.ts.net\\:
SMB                      192.168.15.23   445    JELLYFIN         [*] Enumerated disks:
SMB                      192.168.15.23   445    JELLYFIN         C:
"""

# Real capture: netexec smb 192.168.15.23 -u guest -p WrongPass123 --shares
SAMPLE_SMB_GUEST_DENIED = """\
SMB                      192.168.15.23   445    JELLYFIN         [*] Unix - Samba (name:JELLYFIN) (domain:tail3f8bbe.ts.net) (signing:False) (SMBv1:False) (Null Auth:True)
SMB                      192.168.15.23   445    JELLYFIN         [+] tail3f8bbe.ts.net\\guest:WrongPass123 (Guest)
SMB                      192.168.15.23   445    JELLYFIN         [-] Error enumerating shares: STATUS_ACCESS_DENIED
"""

# Real capture: netexec smb 192.168.15.23 -u "" -p "" --groups (NetExec 1.5.1)
SAMPLE_SMB_GROUPS_REMOVED = """\
SMB                      192.168.15.23   445    JELLYFIN         [*] Unix - Samba (name:JELLYFIN) (domain:tail3f8bbe.ts.net) (signing:False) (SMBv1:False) (Null Auth:True)
SMB                      192.168.15.23   445    JELLYFIN         [+] tail3f8bbe.ts.net\\:
SMB                      192.168.15.23   445    JELLYFIN         [-] [REMOVED] Arg moved to the ldap protocol
"""

# Second host block appended to the real single-host capture above so
# per-host grouping is exercised. Its share rows are formatted with the
# exact NetExec template (f"{name:<15} {perms:<22} {remark}", per
# nxc/protocols/smb.py:1744/1750) -- permissions are ",".join(access), no
# space after the comma.
SAMPLE_TWO_HOSTS = SAMPLE_SMB_SHARES + """\
SMB                      10.10.10.5      445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:corp.local) (signing:True) (SMBv1:False)
SMB                      10.10.10.5      445    DC01             [+] corp.local\\admin:SecretPass123 (Pwn3d!)
SMB                      10.10.10.5      445    DC01             [*] Enumerated shares
SMB                      10.10.10.5      445    DC01             Share           Permissions            Remark
SMB                      10.10.10.5      445    DC01             -----           -----------            ------
SMB                      10.10.10.5      445    DC01             ADMIN$          READ,WRITE             Remote Admin
SMB                      10.10.10.5      445    DC01             SYSVOL          READ                   Logon server share
"""


def test_parse_smb_banner_and_shares():
    parsed = nxe_parse.parse_netexec_output(SAMPLE_SMB_SHARES)
    assert parsed["unparsed_lines"] == 0
    assert len(parsed["hosts"]) == 1

    host = parsed["hosts"][0]
    assert host["host"] == "192.168.15.23"
    assert host["hostname"] == "JELLYFIN"
    assert host["port"] == 445
    assert host["protocol"] == "smb"
    assert host["os"] == "Unix - Samba"
    assert host["domain"] == "tail3f8bbe.ts.net"
    assert host["signing"] is False
    assert host["smbv1"] is False
    assert host["null_auth"] is True
    assert host["auth_success"] is True
    assert host["auth_user"] is None
    assert host["admin_access"] is False

    assert host["shares_count"] == 3
    assert host["shares"] == [
        {"name": "print$", "remark": "Printer Drivers"},
        {"name": "media"},
        {"name": "IPC$", "remark": "IPC Service (Samba 4.17.12-Debian)"},
    ]


def test_parse_smb_users_table():
    host = nxe_parse.parse_netexec_output(SAMPLE_SMB_USERS)["hosts"][0]
    assert host["users_count"] == 1
    assert host["users"][0]["name"] == "nasuser"
    assert "2026-09-15 17:23:38" in host["users"][0]["detail"]
    assert host["errors"] == []


def test_parse_smb_password_policy():
    host = nxe_parse.parse_netexec_output(SAMPLE_SMB_PASS_POL)["hosts"][0]
    policy = host["password_policy"]
    assert policy["domain"] == "JELLYFIN"
    assert policy["Minimum password length"] == "5"
    assert policy["Password history length"] == "None"
    assert policy["Account Lockout Threshold"] == "None"
    assert policy["Password Complexity Flags"] == "000000"


def test_parse_smb_disks():
    host = nxe_parse.parse_netexec_output(SAMPLE_SMB_DISKS)["hosts"][0]
    assert host["disks"] == ["C:"]


def test_parse_guest_auth_and_access_denied_error():
    host = nxe_parse.parse_netexec_output(SAMPLE_SMB_GUEST_DENIED)["hosts"][0]
    assert host["auth_success"] is True
    assert host["auth_user"] == "guest"
    assert host["guest_auth"] is True
    assert host["admin_access"] is False
    assert host["errors"] == ["Error enumerating shares: STATUS_ACCESS_DENIED"]


def test_parse_removed_groups_flag_is_reported_as_error():
    host = nxe_parse.parse_netexec_output(SAMPLE_SMB_GROUPS_REMOVED)["hosts"][0]
    assert host["errors"] == ["[REMOVED] Arg moved to the ldap protocol"]


def test_parse_groups_into_separate_hosts():
    parsed = nxe_parse.parse_netexec_output(SAMPLE_TWO_HOSTS)
    assert parsed["unparsed_lines"] == 0
    assert parsed["hosts"][0]["host"] == "10.10.10.5"
    assert parsed["hosts"][1]["host"] == "192.168.15.23"

    dc = parsed["hosts"][0]
    assert dc["domain"] == "corp.local"
    assert dc["signing"] is True
    assert dc["admin_access"] is True
    assert dc["auth_user"] == "admin"
    assert dc["shares"] == [
        {"name": "ADMIN$", "permissions": "READ,WRITE", "remark": "Remote Admin"},
        {"name": "SYSVOL", "permissions": "READ", "remark": "Logon server share"},
    ]


def test_parse_result_no_output_is_no_response():
    raw = nxe_parse.RawNetexecEnumResult(target="192.168.15.99", protocol="smb")
    result = nxe_parse.parse_netexec_enum_result(raw)
    assert result["status"] == "no_response"
    assert result["hosts_found"] == 0
    assert "no responsive smb service" in result["note"]


def test_parse_result_nonzero_exit_without_host_output_is_failed():
    raw = nxe_parse.RawNetexecEnumResult(
        target="10.0.0.1",
        protocol="smb",
        stderr="netexec: error: unrecognized arguments",
        returncode=2,
    )
    result = nxe_parse.parse_netexec_enum_result(raw)
    assert result["status"] == "failed"
    assert "unrecognized arguments" in result["error"]


def test_parse_result_caps_long_lists_but_keeps_counts():
    lines = [
        "SMB                      10.0.0.1        445    DC01             "
        "[*] Windows Server 2022 x64 (name:DC01) (domain:corp.local) "
        "(signing:True) (SMBv1:False)",
        "SMB                      10.0.0.1        445    DC01             "
        "[*] Enumerated shares",
        "SMB                      10.0.0.1        445    DC01             "
        "Share           Permissions            Remark",
        "SMB                      10.0.0.1        445    DC01             "
        "-----           -----------            ------",
    ]
    for index in range(60):
        lines.append(
            "SMB                      10.0.0.1        445    DC01             "
            f"share{index:02d}                                 Remark"
        )
    raw = nxe_parse.RawNetexecEnumResult(
        target="10.0.0.1", protocol="smb", stdout="\n".join(lines)
    )
    result = nxe_parse.parse_netexec_enum_result(raw)
    host = result["hosts"][0]
    assert host["shares_count"] == 60
    assert len(host["shares"]) == nxe_parse.MAX_SHARES_RETURNED
    assert host["shares_truncated"] is True


def test_redact_credentials():
    redacted = nxe_parse.redact_credentials(SAMPLE_SMB_GUEST_DENIED)
    assert "WrongPass123" not in redacted
    assert "tail3f8bbe.ts.net\\guest:<redacted> (Guest)" in redacted
    # Non-auth rows must be untouched.
    assert "[*] Unix - Samba" in redacted
    assert "[-] Error enumerating shares" in redacted


def test_normalize_target_host():
    assert nxe_parse.normalize_target_host("10.0.0.1") == "10.0.0.1"
    assert nxe_parse.normalize_target_host("10.0.0.0/24") == "10.0.0.0/24"
    assert (
        nxe_parse.normalize_target_host("smb://dc01.corp.local:445")
        == "dc01.corp.local"
    )
    assert nxe_parse.normalize_target_host("dc01.corp.local:445") == "dc01.corp.local"
    assert nxe_parse.normalize_target_host("   ") == ""


def test_build_argv_anonymous_passes_empty_arguments():
    argv = nxe_execute.build_argv(
        target="10.0.0.1",
        protocol="smb",
        shares=True,
        binary="/usr/local/bin/netexec",
    )
    assert argv == [
        "/usr/local/bin/netexec",
        "smb",
        "10.0.0.1",
        "-t",
        "16",
        "--no-progress",
        "-u",
        "",
        "-p",
        "",
        "--shares",
    ]


def test_build_argv_authenticated():
    argv = nxe_execute.build_argv(
        target="10.0.0.1",
        protocol="smb",
        domain="corp.local",
        username="admin",
        password="SecretPass123",
        shares=True,
        users=True,
        pass_pol=True,
        disks=True,
        loggedon_users=True,
    )
    assert argv[:3] == ["netexec", "smb", "10.0.0.1"]
    assert argv[argv.index("-d") + 1] == "corp.local"
    assert argv[argv.index("-u") + 1] == "admin"
    assert argv[argv.index("-p") + 1] == "SecretPass123"
    for flag in ("--shares", "--users", "--pass-pol", "--disks", "--loggedon-users"):
        assert flag in argv


def test_build_argv_hashes():
    argv = nxe_execute.build_argv(
        target="10.0.0.1",
        protocol="smb",
        username="admin",
        hashes="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
        groups=True,
    )
    assert argv[argv.index("-H") + 1].startswith("aad3b435b")
    assert "-p" not in argv
    assert "--groups" in argv


def test_execute_empty_target():
    res = nxe_execute.execute(target="")
    assert "empty target" in res.error.lower()


def test_execute_missing_binary(monkeypatch):
    monkeypatch.setattr(nxe_execute, "find_netexec_binary", lambda: None)
    res = nxe_execute.execute(target="10.0.0.1")
    assert "not found on path" in res.error.lower()


def test_execute_rejects_unsupported_protocol():
    res = nxe_execute.execute(target="10.0.0.1", protocol="telnet")
    assert "unsupported protocol" in res.error.lower()


def test_execute_rejects_broad_cidr():
    res = nxe_execute.execute(target="10.0.0.0/16")
    assert "broader than /24" in res.error


def test_execute_rejects_password_and_hashes_together():
    res = nxe_execute.execute(
        target="10.0.0.1", username="admin", password="pw", hashes="LM:NT"
    )
    assert "at most one" in res.error


def test_execute_timeout(monkeypatch):
    monkeypatch.setattr(nxe_execute, "find_netexec_binary", lambda: "/usr/bin/netexec")

    def mock_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=5)

    res = nxe_execute.execute(target="10.0.0.1", runner=mock_run)
    assert "timed out" in res.error.lower()


def test_execute_success_with_mock_runner(monkeypatch):
    monkeypatch.setattr(nxe_execute, "find_netexec_binary", lambda: "/usr/bin/netexec")

    proc = MagicMock()
    proc.stdout = SAMPLE_SMB_SHARES
    proc.stderr = ""
    proc.returncode = 0

    res = nxe_execute.execute(target="192.168.15.23", runner=lambda *a, **kw: proc)
    assert res.error is None
    assert res.returncode == 0
    assert "Enumerated shares" in res.stdout


def test_tool_wrapper_evidence_and_facts(monkeypatch):
    tool = NetexecEnum()
    assert tool.tool_id == "netexec_enum"
    assert tool.destructive is False

    monkeypatch.setattr(nxe_execute, "find_netexec_binary", lambda: "/usr/bin/netexec")

    proc = MagicMock()
    proc.stdout = SAMPLE_SMB_SHARES
    proc.stderr = ""
    proc.returncode = 0
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: proc)

    result = tool.run(target="192.168.15.23", shares=True)
    assert result["status"] == "success"
    assert result["hosts_found"] == 1
    assert result["hosts"][0]["shares_count"] == 3
    assert "_full_evidence" in result

    evidence = tool.extract_evidence({"target": "192.168.15.23"}, result)
    assert evidence is not None
    ev_target, ev_data = evidence
    assert ev_target == "192.168.15.23"
    assert len(ev_data["hosts"][0]["shares"]) == 3
    assert "Enumerated shares" in ev_data["raw_stdout"]

    result["evidence_id"] = "netexec_enum:192.168.15.23"
    facts = tool.extract_facts({"target": "192.168.15.23"}, result)
    assert len(facts) == 1
    fact = facts[0]
    assert fact["host"] == "192.168.15.23"
    assert fact["port"] == 445
    assert fact["protocol"] == "smb"
    assert fact["ad_domain"] == "tail3f8bbe.ts.net"
    assert fact["smb_signing"] is False
    assert fact["smb_null_auth"] is True
    assert fact["smb_shares_count"] == 3
    assert fact["evidence"] == "netexec_enum:192.168.15.23"


def test_tool_wrapper_multi_host_omits_single_host_evidence_pointer(monkeypatch):
    tool = NetexecEnum()
    monkeypatch.setattr(nxe_execute, "find_netexec_binary", lambda: "/usr/bin/netexec")

    proc = MagicMock()
    proc.stdout = SAMPLE_TWO_HOSTS
    proc.stderr = ""
    proc.returncode = 0
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: proc)

    result = tool.run(target="10.10.10.0/24", shares=True)
    result["evidence_id"] = "netexec_enum:10.10.10.0_24"
    facts = tool.extract_facts({"target": "10.10.10.0/24"}, result)
    assert len(facts) == 2
    assert facts[0]["smb_admin_access"] is True
    assert all("evidence" not in fact for fact in facts)


def test_tool_wrapper_no_response_has_no_facts_or_evidence(monkeypatch):
    tool = NetexecEnum()
    monkeypatch.setattr(nxe_execute, "find_netexec_binary", lambda: "/usr/bin/netexec")

    proc = MagicMock()
    proc.stdout = ""
    proc.stderr = ""
    proc.returncode = 0
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: proc)

    result = tool.run(target="192.168.15.99")
    assert result["status"] == "no_response"
    assert "_full_evidence" not in result
    assert tool.extract_evidence({"target": "192.168.15.99"}, result) is None
    assert tool.extract_facts({"target": "192.168.15.99"}, result) == []


def test_tool_is_available_accepts_nxc_alias(monkeypatch):
    tool = NetexecEnum()
    monkeypatch.setattr(nxe_execute, "find_netexec_binary", lambda: "/usr/bin/nxc")
    assert tool.is_available() is True

    monkeypatch.setattr(nxe_execute, "find_netexec_binary", lambda: None)
    assert tool.is_available() is False


def test_netexec_enum_profile_membership():
    assert "netexec_enum" in load_profile("ad-network")


FAKE_CCACHE_B64 = base64.b64encode(b"FAKE_CCACHE_BYTES").decode()


def test_ccache_b64_rejects_combination_with_password(monkeypatch):
    monkeypatch.setattr(nxe_execute, "find_netexec_binary", lambda: "/usr/bin/netexec")
    res = nxe_execute.execute(target="10.0.0.1", password="x", ccache_b64=FAKE_CCACHE_B64)
    assert "mutually exclusive" in (res.error or "")


def test_ccache_b64_rejects_invalid_base64(monkeypatch):
    monkeypatch.setattr(nxe_execute, "find_netexec_binary", lambda: "/usr/bin/netexec")
    res = nxe_execute.execute(target="10.0.0.1", ccache_b64="not-valid-base64!!")
    assert "not valid base64" in (res.error or "")


def test_ccache_b64_uses_use_kcache_flag_not_bare_k(monkeypatch):
    # NetExec lists -k/--kerberos and --use-kcache as two independent
    # flags (confirmed against the real installed binary's --help); only
    # --use-kcache actually reads KRB5CCNAME.
    monkeypatch.setattr(nxe_execute, "find_netexec_binary", lambda: "/usr/bin/netexec")
    calls = []

    def fake_runner(*args, **kwargs):
        # The ccache file only exists for the duration of this call --
        # execute() deletes its disposable temp dir right after the
        # subprocess call returns -- so read it here, not after execute()
        # has already returned.
        env = kwargs.get("env")
        with open(env["KRB5CCNAME"], "rb") as f:
            calls.append((args, kwargs, f.read()))
        return MagicMock(stdout="", stderr="", returncode=0)

    nxe_execute.execute(target="10.0.0.1", ccache_b64=FAKE_CCACHE_B64, runner=fake_runner)
    assert len(calls) == 1
    args, kwargs, ccache_contents = calls[0]
    argv = args[0]
    assert "--use-kcache" in argv
    assert "-p" not in argv  # no empty -p fallback when using a ccache
    assert "KRB5CCNAME" in kwargs.get("env", {})
    assert ccache_contents == b"FAKE_CCACHE_BYTES"


def test_no_ccache_b64_still_passes_empty_dash_p(monkeypatch):
    # Regression: confirms the existing anonymous-session default wasn't
    # broken by the use_kcache branch.
    argv = nxe_execute.build_argv(target="10.0.0.1")
    assert argv[argv.index("-p") + 1] == ""


def test_ccache_write_io_error_returns_clean_error_not_raised(monkeypatch):
    # Regression: materializing the ccache file (open/write/chmod) must
    # be caught by the same except that wraps the subprocess call -- a
    # prior version put it in an outer try with only a `finally`, so an
    # I/O error here would propagate uncaught out of execute().
    monkeypatch.setattr(nxe_execute, "find_netexec_binary", lambda: "/usr/bin/netexec")
    monkeypatch.setattr(nxe_execute.os, "chmod", lambda *a, **kw: (_ for _ in ()).throw(OSError("disk full")))
    res = nxe_execute.execute(
        target="10.0.0.1", ccache_b64=FAKE_CCACHE_B64,
        runner=lambda *a, **kw: MagicMock(stdout="", stderr="", returncode=0),
    )
    assert res.error is not None and "disk full" in res.error
