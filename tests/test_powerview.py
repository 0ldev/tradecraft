"""
Unit tests for powerview adapter, parser, contract, and Tool wrapper.
"""
from __future__ import annotations

import base64
import subprocess
from typing import Any, Dict
from unittest.mock import MagicMock

from tradecraft.adapters.powerview import execute as pv_execute
from tradecraft.adapters.powerview import parse as pv_parse
from tradecraft.tools.powerview import PowerView
from tradecraft.tools.profiles import load_profile

SAMPLE_USER_OUTPUT = """
Logging directory is set to /root/.powerview/logs/corp
sAMAccountName                 : Administrator
distinguishedName              : CN=Administrator,CN=Users,DC=corp,DC=local
adminCount                     : 1
memberOf                       : CN=Domain Admins,CN=Users,DC=corp,DC=local
                                 CN=Administrators,CN=Builtin,DC=corp,DC=local
userPrincipalName              : administrator@corp.local
servicePrincipalName           : MSSQLSvc/db01.corp.local:1433

sAMAccountName                 : krbtgt
distinguishedName              : CN=krbtgt,CN=Users,DC=corp,DC=local
adminCount                     : 1
description                    : Key Distribution Center Service Account

sAMAccountName                 : jdoe
distinguishedName              : CN=John Doe,CN=Users,DC=corp,DC=local
adminCount                     : 0
mail                           : jdoe@corp.local
"""

SAMPLE_COMPUTER_OUTPUT = """
sAMAccountName                 : DC01$
dNSHostName                    : dc01.corp.local
operatingSystem                : Windows Server 2022 Standard
distinguishedName              : CN=DC01,OU=Domain Controllers,DC=corp,DC=local

sAMAccountName                 : WS01$
dNSHostName                    : ws01.corp.local
operatingSystem                : Windows 11 Enterprise
distinguishedName              : CN=WS01,CN=Computers,DC=corp,DC=local
"""

SAMPLE_GROUP_OUTPUT = """
sAMAccountName                 : Domain Admins
distinguishedName              : CN=Domain Admins,CN=Users,DC=corp,DC=local
adminCount                     : 1

sAMAccountName                 : IT Support
distinguishedName              : CN=IT Support,CN=Users,DC=corp,DC=local
adminCount                     : 0
"""

SAMPLE_TRUST_OUTPUT = """
TargetName                     : dev.corp.local
TrustPartner                   : dev.corp.local
TrustDirection                 : Bidirectional
TrustType                      : UpLevel
"""

SAMPLE_DC_OUTPUT = """
Name                           : DC01.corp.local
dNSHostName                    : dc01.corp.local
IPAddress                      : 10.0.0.1
"""

SAMPLE_ERROR_OUTPUT = """
Logging directory is set to /root/.powerview/logs/corp
socket connection error while opening: [Errno 111] Connection refused
"""


def test_build_argv_anonymous():
    argv = pv_execute.build_argv(
        target="10.0.0.1",
        domain="corp.local",
        query="Get-Domain",
        binary="/usr/local/bin/powerview",
    )
    assert argv == [
        "/usr/local/bin/powerview",
        "10.0.0.1",
        "--dc-ip",
        "10.0.0.1",
        "-q",
        "Get-Domain",
        "--no-cache",
        "--no-admin-check",
        "--no-pass",
    ]


def test_build_argv_authenticated():
    argv = pv_execute.build_argv(
        target="10.0.0.1",
        domain="corp.local",
        username="admin",
        password="SecretPassword123",
        query="Get-DomainUser",
        use_ldap=True,
    )
    assert argv[0] == "powerview"
    assert argv[1] == "corp.local/admin:SecretPassword123@10.0.0.1"
    assert "--dc-ip" in argv
    assert "-q" in argv
    assert "Get-DomainUser" in argv
    assert "--use-ldap" in argv
    assert "--no-pass" not in argv


def test_build_argv_hashes_and_kerberos():
    argv = pv_execute.build_argv(
        target="10.0.0.1",
        domain="corp.local",
        username="admin",
        hashes="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
        kerberos=True,
    )
    assert "-H" in argv
    assert "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0" in argv
    assert "-k" in argv
    assert "--no-pass" not in argv


def test_parse_powerview_blocks_and_insights_users():
    entries = pv_parse.parse_powerview_blocks(SAMPLE_USER_OUTPUT)
    assert len(entries) == 3
    assert entries[0]["sAMAccountName"] == "Administrator"
    assert entries[0]["adminCount"] == "1"
    assert isinstance(entries[0]["memberOf"], list)
    assert len(entries[0]["memberOf"]) == 2
    assert "CN=Domain Admins,CN=Users,DC=corp,DC=local" in entries[0]["memberOf"]
    assert entries[0]["servicePrincipalName"] == "MSSQLSvc/db01.corp.local:1433"

    assert entries[1]["sAMAccountName"] == "krbtgt"
    assert entries[2]["sAMAccountName"] == "jdoe"
    assert entries[2]["mail"] == "jdoe@corp.local"

    insights = pv_parse.extract_query_insights("Get-DomainUser", entries)
    assert insights["total_count"] == 3
    assert insights["users"] == ["Administrator", "jdoe", "krbtgt"]
    assert insights["admin_users"] == ["Administrator", "krbtgt"]
    assert insights["kerberoastable_users"] == ["Administrator"]


def test_parse_powerview_blocks_computers():
    entries = pv_parse.parse_powerview_blocks(SAMPLE_COMPUTER_OUTPUT)
    assert len(entries) == 2
    assert entries[0]["dNSHostName"] == "dc01.corp.local"
    assert entries[1]["dNSHostName"] == "ws01.corp.local"

    insights = pv_parse.extract_query_insights("Get-DomainComputer", entries)
    assert insights["total_count"] == 2
    assert insights["computers"] == ["dc01.corp.local", "ws01.corp.local"]
    assert "Windows Server 2022 Standard" in insights["operating_systems"]
    assert "Windows 11 Enterprise" in insights["operating_systems"]


def test_parse_powerview_blocks_groups():
    entries = pv_parse.parse_powerview_blocks(SAMPLE_GROUP_OUTPUT)
    assert len(entries) == 2
    insights = pv_parse.extract_query_insights("Get-DomainGroup", entries)
    assert insights["total_count"] == 2
    assert insights["groups"] == ["Domain Admins", "IT Support"]
    assert insights["admin_groups"] == ["Domain Admins"]


def test_parse_powerview_blocks_trusts():
    entries = pv_parse.parse_powerview_blocks(SAMPLE_TRUST_OUTPUT)
    assert len(entries) == 1
    insights = pv_parse.extract_query_insights("Get-DomainTrust", entries)
    assert insights["trusts"] == ["dev.corp.local"]


def test_parse_powerview_blocks_dcs():
    entries = pv_parse.parse_powerview_blocks(SAMPLE_DC_OUTPUT)
    assert len(entries) == 1
    insights = pv_parse.extract_query_insights("Get-DomainController", entries)
    assert insights["domain_controllers"] == ["dc01.corp.local"]


def test_detect_powerview_error():
    err = pv_parse.detect_powerview_error(SAMPLE_ERROR_OUTPUT, "")
    assert err is not None
    assert "connection refused" in err.lower()


def test_parse_powerview_result_success():
    raw = pv_parse.RawPowerViewResult(
        target="10.0.0.1",
        domain="corp.local",
        query="Get-DomainUser",
        stdout=SAMPLE_USER_OUTPUT,
        returncode=0,
    )
    result = pv_parse.parse_powerview_result(raw)
    assert result["status"] == "success"
    assert result["total_entries"] == 3
    assert len(result["entries"]) == 3
    assert "insights" in result
    assert result["insights"]["admin_users"] == ["Administrator", "krbtgt"]
    assert result.get("error") is None


def test_parse_powerview_result_failure():
    raw = pv_parse.RawPowerViewResult(
        target="10.0.0.1",
        domain="corp.local",
        query="Get-DomainUser",
        stdout=SAMPLE_ERROR_OUTPUT,
        returncode=0,
    )
    result = pv_parse.parse_powerview_result(raw)
    assert result["status"] == "failed"
    assert result["total_entries"] == 0
    assert "connection refused" in result["error"].lower()


def test_execute_empty_target_and_domain():
    res1 = pv_execute.execute(target="", domain="corp.local")
    assert "empty target" in res1.error.lower()

    res2 = pv_execute.execute(target="10.0.0.1", domain="")
    assert "missing required" in res2.error.lower()


def test_execute_missing_binary(monkeypatch):
    monkeypatch.setattr(pv_execute, "find_powerview_binary", lambda: None)
    res = pv_execute.execute(target="10.0.0.1", domain="corp.local")
    assert "not found on path" in res.error.lower()


def test_execute_timeout(monkeypatch):
    monkeypatch.setattr(pv_execute, "find_powerview_binary", lambda: "/usr/local/bin/powerview")

    def mock_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=5)

    res = pv_execute.execute(target="10.0.0.1", domain="corp.local", runner=mock_run)
    assert "timed out" in res.error.lower()


def test_execute_success_with_mock_runner(monkeypatch):
    monkeypatch.setattr(pv_execute, "find_powerview_binary", lambda: "/usr/local/bin/powerview")

    mock_proc = MagicMock()
    mock_proc.stdout = SAMPLE_USER_OUTPUT
    mock_proc.stderr = ""
    mock_proc.returncode = 0

    res = pv_execute.execute(target="10.0.0.1", domain="corp.local", runner=lambda *a, **kw: mock_proc)
    assert res.returncode == 0
    assert res.target == "10.0.0.1"
    assert res.domain == "corp.local"
    assert "Administrator" in res.stdout


def test_powerview_tool_wrapper(monkeypatch):
    tool = PowerView()
    assert tool.tool_id == "powerview"
    assert tool.destructive is False

    mock_proc = MagicMock()
    mock_proc.stdout = SAMPLE_USER_OUTPUT
    mock_proc.stderr = ""
    mock_proc.returncode = 0

    monkeypatch.setattr(pv_execute, "find_powerview_binary", lambda: "/usr/local/bin/powerview")
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: mock_proc)

    result = tool.run(
        target="10.0.0.1",
        domain="corp.local",
        username="admin",
        password="SecretPassword123",
        query="Get-DomainUser",
    )
    assert result["status"] == "success"
    assert result["total_entries"] == 3
    assert "_full_evidence" in result

    evidence_res = tool.extract_evidence(
        {"target": "10.0.0.1", "domain": "corp.local"},
        result,
    )
    assert evidence_res is not None
    host, full_data = evidence_res
    assert host == "10.0.0.1"
    assert full_data["total_entries"] == 3
    assert full_data["domain"] == "corp.local"

    # Test extract_facts
    result["evidence_id"] = "ev_powerview_1"
    facts = tool.extract_facts({"target": "10.0.0.1", "domain": "corp.local"}, result)
    assert len(facts) == 1
    fact = facts[0]
    assert fact["host"] == "10.0.0.1"
    assert fact["ad_domain"] == "corp.local"
    assert fact["ad_objects_count"] == 3
    assert fact["ad_users_count"] == 3
    assert fact["ad_admin_users_count"] == 2
    assert fact["ad_kerberoastable_users_count"] == 1
    assert fact["evidence"] == "ev_powerview_1"


def test_powerview_profile_membership():
    tool_ids = load_profile("ad-network")
    assert "powerview" in tool_ids


SAMPLE_GET_DOMAIN_OUTPUT = """
Logging directory is set to /root/.powerview/logs/corp
distinguishedName              : DC=corp,DC=local
name                           : corp
objectSid                      : S-1-5-21-111-222-333
whenCreated                    : 1/1/2020 12:00:00 AM
"""


def test_parse_powerview_get_domain_populates_domain_sid():
    entries = pv_parse.parse_powerview_blocks(SAMPLE_GET_DOMAIN_OUTPUT)
    assert len(entries) == 1
    insights = pv_parse.extract_query_insights("Get-Domain", entries)
    assert insights["total_count"] == 1
    assert insights["domain_sid"] == "S-1-5-21-111-222-333"


def test_parse_powerview_get_domain_without_object_sid_has_no_domain_sid():
    entries = pv_parse.parse_powerview_blocks("name : corp\n")
    insights = pv_parse.extract_query_insights("Get-Domain", entries)
    assert "domain_sid" not in insights


def test_domain_branch_does_not_steal_trust_or_controller_queries():
    # Get-DomainTrust / Get-DomainController contain "domain" in their query string.
    # They must still hit their own branches, and must not get a domain_sid key.
    # Entries here carry objectSid to prove the domain branch would have matched
    # if it had won the elif chain.
    entries_with_sid = [{
        "objectSid": "S-1-5-21-111-222-333",
        "TargetName": "dev.corp.local",
        "dNSHostName": "dc01.corp.local",
    }]

    trust = pv_parse.extract_query_insights("Get-DomainTrust", entries_with_sid)
    assert trust["trusts"] == ["dev.corp.local"]
    assert "domain_sid" not in trust
    assert "domain_controllers" not in trust

    dc = pv_parse.extract_query_insights("Get-DomainController", entries_with_sid)
    assert dc["domain_controllers"] == ["dc01.corp.local"]
    assert "domain_sid" not in dc
    assert "trusts" not in dc


def test_domain_branch_does_not_match_other_domain_cmdlets():
    # query is a free-text PowerView command string (config/tools/powerview.yaml),
    # not limited to the six cmdlets named in its description. Any real cmdlet
    # whose name merely contains "domain" -- Get-DomainObject, Get-DomainOU,
    # Get-DomainPolicy, Get-DomainDNSZone, etc. -- must NOT be mislabeled with
    # a domain_sid from whatever unrelated object's objectSid happens to be
    # in its output.
    entries_with_sid = [{"objectSid": "S-1-5-21-999-888-777", "name": "some-object"}]
    for query in ("Get-DomainObject", "Get-DomainOU", "Get-DomainPolicy", "Get-DomainDNSZone"):
        insights = pv_parse.extract_query_insights(query, entries_with_sid)
        assert "domain_sid" not in insights, f"{query} must not get a domain_sid"


def test_domain_branch_matches_get_domain_with_trailing_arguments():
    # query may carry trailing arguments after the cmdlet name; only the first
    # whitespace-delimited token decides the branch.
    entries = pv_parse.parse_powerview_blocks(SAMPLE_GET_DOMAIN_OUTPUT)
    insights = pv_parse.extract_query_insights("Get-Domain -Domain corp.local", entries)
    assert insights["domain_sid"] == "S-1-5-21-111-222-333"


FAKE_CCACHE_B64 = base64.b64encode(b"FAKE_CCACHE_BYTES").decode()


def test_ccache_b64_requires_kerberos_true(monkeypatch):
    monkeypatch.setattr(pv_execute, "find_powerview_binary", lambda: "/usr/local/bin/powerview")
    res = pv_execute.execute(
        target="dc01.corp.local", domain="corp.local", ccache_b64=FAKE_CCACHE_B64, kerberos=False,
    )
    assert "requires kerberos" in (res.error or "")


def test_kerberos_with_ip_target_is_rejected(monkeypatch):
    # Confirmed live against the real binary: powerview's -k fails with
    # "Kerberos authentication requires FQDN instead of IP" for a bare IP
    # target -- Kerberos service tickets are bound to a hostname (SPN).
    monkeypatch.setattr(pv_execute, "find_powerview_binary", lambda: "/usr/local/bin/powerview")
    with_mock = MagicMock()

    def fake_runner(*args, **kwargs):
        with_mock()
        return MagicMock(stdout="", stderr="", returncode=0)

    res = pv_execute.execute(target="10.0.0.1", domain="corp.local", kerberos=True, runner=fake_runner)
    assert "hostname/FQDN" in (res.error or "")
    with_mock.assert_not_called()


def test_kerberos_with_hostname_target_is_accepted(monkeypatch):
    monkeypatch.setattr(pv_execute, "find_powerview_binary", lambda: "/usr/local/bin/powerview")
    res = pv_execute.execute(
        target="dc01.corp.local", domain="corp.local", kerberos=True,
        runner=lambda *a, **kw: MagicMock(stdout="", stderr="", returncode=0),
    )
    assert res.error is None


def test_ccache_b64_rejects_invalid_base64(monkeypatch):
    monkeypatch.setattr(pv_execute, "find_powerview_binary", lambda: "/usr/local/bin/powerview")
    res = pv_execute.execute(
        target="dc01.corp.local", domain="corp.local", ccache_b64="not-valid-base64!!", kerberos=True,
    )
    assert "not valid base64" in (res.error or "")


def test_ccache_b64_materializes_krb5ccname_env(monkeypatch):
    monkeypatch.setattr(pv_execute, "find_powerview_binary", lambda: "/usr/local/bin/powerview")
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

    pv_execute.execute(
        target="dc01.corp.local", domain="corp.local", ccache_b64=FAKE_CCACHE_B64, kerberos=True, runner=fake_runner,
    )
    assert len(calls) == 1
    args, kwargs, ccache_contents = calls[0]
    assert "-k" in args[0]
    assert "KRB5CCNAME" in kwargs.get("env", {})
    assert ccache_contents == b"FAKE_CCACHE_BYTES"


def test_no_ccache_b64_passes_default_env(monkeypatch):
    monkeypatch.setattr(pv_execute, "find_powerview_binary", lambda: "/usr/local/bin/powerview")
    calls = []

    def fake_runner(*args, **kwargs):
        calls.append(kwargs)
        return MagicMock(stdout="", stderr="", returncode=0)

    pv_execute.execute(target="dc01.corp.local", domain="corp.local", runner=fake_runner)
    assert calls[0].get("env") is None


def test_ccache_write_io_error_returns_clean_error_not_raised(monkeypatch):
    # Regression: materializing the ccache file (open/write/chmod) must
    # be caught by the same except that wraps the subprocess call -- a
    # prior version put it in an outer try with only a `finally`, so an
    # I/O error here would propagate uncaught out of execute().
    monkeypatch.setattr(pv_execute, "find_powerview_binary", lambda: "/usr/local/bin/powerview")
    monkeypatch.setattr(pv_execute.os, "chmod", lambda *a, **kw: (_ for _ in ()).throw(OSError("disk full")))
    res = pv_execute.execute(
        target="dc01.corp.local", domain="corp.local", ccache_b64=FAKE_CCACHE_B64, kerberos=True,
        runner=lambda *a, **kw: MagicMock(stdout="", stderr="", returncode=0),
    )
    assert res.error is not None and "disk full" in res.error
