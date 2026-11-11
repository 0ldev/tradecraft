"""
Unit tests for bloodhound adapter, parser, contract, and Tool wrapper.
"""
from __future__ import annotations

import base64
import json
import subprocess
from typing import Any, Dict
from unittest.mock import MagicMock

from tradecraft.adapters.bloodhound import execute as bh_execute
from tradecraft.adapters.bloodhound import parse as bh_parse
from tradecraft.tools.bloodhound import Bloodhound
from tradecraft.tools.profiles import load_profile

SAMPLE_USERS_JSON = json.dumps({
    "data": [
        {
            "Properties": {
                "name": "ADMINISTRATOR@CORP.LOCAL",
                "samaccountname": "Administrator",
                "admincount": True,
                "serviceprincipalnames": ["MSSQLSvc/db01.corp.local:1433"],
                "enabled": True,
            },
            "Aces": [],
        },
        {
            "Properties": {
                "name": "KRBTGT@CORP.LOCAL",
                "samaccountname": "krbtgt",
                "admincount": True,
                "serviceprincipalnames": [],
                "enabled": True,
            },
            "Aces": [],
        },
        {
            "Properties": {
                "name": "JDOE@CORP.LOCAL",
                "samaccountname": "jdoe",
                "admincount": False,
                "serviceprincipalnames": [],
                "enabled": True,
            },
            "Aces": [],
        },
    ],
    "meta": {"count": 3, "type": "users", "version": 4},
})

SAMPLE_GROUPS_JSON = json.dumps({
    "data": [
        {
            "Properties": {
                "name": "DOMAIN ADMINS@CORP.LOCAL",
                "admincount": True,
            },
            "Members": [],
        },
        {
            "Properties": {
                "name": "IT SUPPORT@CORP.LOCAL",
                "admincount": False,
            },
            "Members": [],
        },
    ],
    "meta": {"count": 2, "type": "groups", "version": 4},
})

SAMPLE_COMPUTERS_JSON = json.dumps({
    "data": [
        {
            "Properties": {
                "name": "DC01.CORP.LOCAL",
                "operatingsystem": "Windows Server 2022 Standard",
                "enabled": True,
            },
        },
        {
            "Properties": {
                "name": "WS01.CORP.LOCAL",
                "operatingsystem": "Windows 11 Enterprise",
                "enabled": True,
            },
        },
    ],
    "meta": {"count": 2, "type": "computers", "version": 4},
})

SAMPLE_DOMAINS_JSON = json.dumps({
    "data": [
        {
            "Properties": {
                "name": "CORP.LOCAL",
                "domain": "CORP.LOCAL",
            },
            "Trusts": [
                {"TargetName": "DEV.CORP.LOCAL", "TrustDirection": "Bidirectional"},
            ],
        },
    ],
    "meta": {"count": 1, "type": "domains", "version": 4},
})

SAMPLE_OUS_JSON = json.dumps({
    "data": [
        {"Properties": {"name": "DOMAIN CONTROLLERS@CORP.LOCAL"}},
        {"Properties": {"name": "WORKSTATIONS@CORP.LOCAL"}},
    ],
    "meta": {"count": 2, "type": "ous", "version": 4},
})


def test_build_argv_anonymous():
    argv = bh_execute.build_argv(
        target="10.0.0.1",
        domain="corp.local",
        collection_method="DCOnly",
        binary="/usr/local/bin/bloodhound-python",
    )
    assert argv == [
        "/usr/local/bin/bloodhound-python",
        "-d",
        "corp.local",
        "-dc",
        "10.0.0.1",
        "-c",
        "DCOnly",
        "-op",
        "bloodhound_run",
        "-no-pass",
        "-ns",
        "10.0.0.1",
    ]


def test_build_argv_authenticated():
    argv = bh_execute.build_argv(
        target="10.0.0.1",
        domain="corp.local",
        username="admin",
        password="SecretPassword123",
        collection_method="All",
        use_ldaps=True,
    )
    assert argv[0] == "bloodhound-python"
    assert "-d" in argv and "corp.local" in argv
    assert "-u" in argv and "admin" in argv
    assert "-p" in argv and "SecretPassword123" in argv
    assert "-c" in argv and "All" in argv
    assert "--use-ldaps" in argv
    assert "-no-pass" not in argv


def test_build_argv_hashes_and_kerberos():
    argv = bh_execute.build_argv(
        target="10.0.0.1",
        domain="corp.local",
        username="admin",
        hashes="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
        kerberos=True,
    )
    assert "--hashes" in argv
    assert "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0" in argv
    assert "-no-pass" not in argv


def test_parse_bloodhound_json_files():
    json_files = {
        "20261103_users.json": SAMPLE_USERS_JSON,
        "20261103_groups.json": SAMPLE_GROUPS_JSON,
        "20261103_computers.json": SAMPLE_COMPUTERS_JSON,
        "20261103_domains.json": SAMPLE_DOMAINS_JSON,
        "20261103_ous.json": SAMPLE_OUS_JSON,
    }
    summary = bh_parse.parse_bloodhound_json_files(json_files)
    assert summary["counts"]["users"] == 3
    assert summary["counts"]["groups"] == 2
    assert summary["counts"]["computers"] == 2
    assert summary["counts"]["domains"] == 1
    assert summary["counts"]["ous"] == 2

    assert "ADMINISTRATOR@CORP.LOCAL" in summary["users"]
    assert "ADMINISTRATOR@CORP.LOCAL" in summary["admin_users"]
    assert "ADMINISTRATOR@CORP.LOCAL" in summary["kerberoastable_users"]

    assert "DOMAIN ADMINS@CORP.LOCAL" in summary["groups"]
    assert "DOMAIN ADMINS@CORP.LOCAL" in summary["admin_groups"]

    assert "DC01.CORP.LOCAL" in summary["computers"]
    assert "Windows Server 2022 Standard" in summary["operating_systems"]
    assert "DEV.CORP.LOCAL" in summary["trusts"]


def test_detect_bloodhound_error():
    err = bh_parse.detect_bloodhound_error("", "dns.resolver.LifetimeTimeout: The resolution lifetime expired after 3.104 seconds")
    assert err is not None
    assert "timeout" in err.lower()


def test_parse_bloodhound_result_success():
    raw = bh_parse.RawBloodhoundResult(
        target="10.0.0.1",
        domain="corp.local",
        collection_method="DCOnly",
        json_files={
            "bh_users.json": SAMPLE_USERS_JSON,
            "bh_groups.json": SAMPLE_GROUPS_JSON,
        },
        returncode=0,
    )
    result = bh_parse.parse_bloodhound_result(raw)
    assert result["status"] == "success"
    assert result["total_objects_collected"] == 5
    assert result["counts"]["users"] == 3
    assert result["counts"]["groups"] == 2
    assert len(result["insights"]["admin_users"]) == 2
    assert "ADMINISTRATOR@CORP.LOCAL" in result["insights"]["admin_users"]
    assert "KRBTGT@CORP.LOCAL" in result["insights"]["admin_users"]
    assert result.get("error") is None


def test_parse_bloodhound_result_failure():
    raw = bh_parse.RawBloodhoundResult(
        target="10.0.0.1",
        domain="corp.local",
        collection_method="DCOnly",
        stderr="Failed to connect to LDAP server on 10.0.0.1: Connection refused",
        returncode=1,
    )
    result = bh_parse.parse_bloodhound_result(raw)
    assert result["status"] == "failed"
    assert result["total_objects_collected"] == 0
    assert "connection refused" in result["error"].lower()


def test_execute_empty_target_and_domain():
    res1 = bh_execute.execute(target="", domain="corp.local")
    assert "empty target" in res1.error.lower()

    res2 = bh_execute.execute(target="10.0.0.1", domain="")
    assert "missing required" in res2.error.lower()


def test_execute_missing_binary(monkeypatch):
    monkeypatch.setattr(bh_execute, "find_bloodhound_binary", lambda: None)
    res = bh_execute.execute(target="10.0.0.1", domain="corp.local")
    assert "not found on path" in res.error.lower()


def test_execute_timeout(monkeypatch):
    monkeypatch.setattr(bh_execute, "find_bloodhound_binary", lambda: "/usr/local/bin/bloodhound-python")

    def mock_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=5)

    res = bh_execute.execute(target="10.0.0.1", domain="corp.local", runner=mock_run)
    assert "timed out" in res.error.lower()


def test_execute_success_with_mock_runner(monkeypatch, tmp_path):
    monkeypatch.setattr(bh_execute, "find_bloodhound_binary", lambda: "/usr/local/bin/bloodhound-python")

    def mock_run(argv, cwd=None, **kwargs):
        # Emulate bloodhound writing a json file in the cwd
        if cwd:
            with open(f"{cwd}/bh_collect_users.json", "w") as f:
                f.write(SAMPLE_USERS_JSON)
        mock_proc = MagicMock()
        mock_proc.stdout = "INFO: Found 3 users\nINFO: Done"
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        return mock_proc

    res = bh_execute.execute(target="10.0.0.1", domain="corp.local", runner=mock_run)
    assert res.returncode == 0
    assert "bh_collect_users.json" in res.json_files
    assert res.error is None


def test_bloodhound_tool_wrapper(monkeypatch):
    tool = Bloodhound()
    assert tool.tool_id == "bloodhound"
    assert tool.destructive is False

    def mock_run(argv, cwd=None, **kwargs):
        if cwd:
            with open(f"{cwd}/bh_collect_users.json", "w") as f:
                f.write(SAMPLE_USERS_JSON)
            with open(f"{cwd}/bh_collect_computers.json", "w") as f:
                f.write(SAMPLE_COMPUTERS_JSON)
        mock_proc = MagicMock()
        mock_proc.stdout = "INFO: Collection finished"
        mock_proc.stderr = ""
        mock_proc.returncode = 0
        return mock_proc

    monkeypatch.setattr(bh_execute, "find_bloodhound_binary", lambda: "/usr/local/bin/bloodhound-python")
    monkeypatch.setattr(subprocess, "run", mock_run)

    result = tool.run(
        target="10.0.0.1",
        domain="corp.local",
        username="admin",
        password="SecretPassword123",
        collection_method="DCOnly",
    )
    assert result["status"] == "success"
    assert result["total_objects_collected"] == 5
    assert "_full_evidence" in result

    evidence_res = tool.extract_evidence(
        {"target": "10.0.0.1", "domain": "corp.local"},
        result,
    )
    assert evidence_res is not None
    host, full_data = evidence_res
    assert host == "10.0.0.1"
    assert full_data["total_objects_collected"] == 5
    assert "bh_collect_users.json" in full_data["json_files"]

    # Test extract_facts
    result["evidence_id"] = "ev_bloodhound_1"
    facts = tool.extract_facts({"target": "10.0.0.1", "domain": "corp.local"}, result)
    assert len(facts) == 1
    fact = facts[0]
    assert fact["host"] == "10.0.0.1"
    assert fact["ad_domain"] == "corp.local"
    assert fact["ad_bloodhound_objects_count"] == 5
    assert fact["ad_users_count"] == 3
    assert fact["ad_computers_count"] == 2
    assert fact["evidence"] == "ev_bloodhound_1"


def test_bloodhound_profile_membership():
    tool_ids = load_profile("ad-network")
    assert "bloodhound" in tool_ids


def test_parse_bloodhound_domain_sids_from_top_level_object_identifier():
    # ObjectIdentifier is top-level on each domains.json item, not under Properties.
    # Two items share one SID (duplicate) and one is a trusted domain with its own SID.
    domains_json = json.dumps({
        "data": [
            {
                "ObjectIdentifier": "S-1-5-21-111-222-333",
                "Properties": {"name": "CORP.LOCAL", "domain": "CORP.LOCAL"},
                "Trusts": [],
            },
            {
                "ObjectIdentifier": "S-1-5-21-111-222-333",
                "Properties": {"name": "CORP.LOCAL", "domain": "CORP.LOCAL"},
                "Trusts": [],
            },
            {
                "ObjectIdentifier": "S-1-5-21-444-555-666",
                "Properties": {"name": "DEV.CORP.LOCAL", "domain": "DEV.CORP.LOCAL"},
                "Trusts": [],
            },
        ],
        "meta": {"count": 3, "type": "domains", "version": 4},
    })
    summary = bh_parse.parse_bloodhound_json_files({"20261103_domains.json": domains_json})
    assert summary["domain_sids"] == ["S-1-5-21-111-222-333", "S-1-5-21-444-555-666"]
    assert summary["domains"] == ["CORP.LOCAL", "DEV.CORP.LOCAL"]

    result = bh_parse.parse_bloodhound_result(bh_parse.RawBloodhoundResult(
        target="10.0.0.1",
        domain="corp.local",
        json_files={"20261103_domains.json": domains_json},
    ))
    assert result["insights"]["domain_sids"] == ["S-1-5-21-111-222-333", "S-1-5-21-444-555-666"]


def test_parse_bloodhound_domain_sids_ignores_nested_object_identifier():
    # An ObjectIdentifier only under Properties must NOT be read as the domain SID.
    domains_json = json.dumps({
        "data": [
            {"Properties": {"name": "CORP.LOCAL", "ObjectIdentifier": "S-1-5-21-999"}},
        ],
        "meta": {"count": 1, "type": "domains", "version": 4},
    })
    summary = bh_parse.parse_bloodhound_json_files({"20261103_domains.json": domains_json})
    assert summary["domain_sids"] == []


FAKE_CCACHE_B64 = base64.b64encode(b"FAKE_CCACHE_BYTES").decode()


def test_ccache_b64_requires_kerberos_true(monkeypatch):
    monkeypatch.setattr(bh_execute, "find_bloodhound_binary", lambda: "/usr/local/bin/bloodhound-python")
    res = bh_execute.execute(
        target="dc01.corp.local", domain="corp.local", ccache_b64=FAKE_CCACHE_B64, kerberos=False,
    )
    assert "requires kerberos" in (res.error or "")


def test_ccache_b64_rejects_invalid_base64(monkeypatch):
    monkeypatch.setattr(bh_execute, "find_bloodhound_binary", lambda: "/usr/local/bin/bloodhound-python")
    res = bh_execute.execute(
        target="dc01.corp.local", domain="corp.local", username="testuser",
        ccache_b64="not-valid-base64!!", kerberos=True,
    )
    assert "not valid base64" in (res.error or "")


def test_ccache_b64_without_username_is_rejected(monkeypatch):
    # Confirmed live against the real binary: bloodhound-python's -k fails
    # with "Specifying the username explicitly is required for Kerberos
    # ccache authentication" when no username is given.
    monkeypatch.setattr(bh_execute, "find_bloodhound_binary", lambda: "/usr/local/bin/bloodhound-python")
    res = bh_execute.execute(
        target="dc01.corp.local", domain="corp.local", ccache_b64=FAKE_CCACHE_B64, kerberos=True,
    )
    assert "username is required" in (res.error or "")


def test_ccache_b64_materializes_krb5ccname_env(monkeypatch):
    monkeypatch.setattr(bh_execute, "find_bloodhound_binary", lambda: "/usr/local/bin/bloodhound-python")
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

    bh_execute.execute(
        target="dc01.corp.local", domain="corp.local", username="testuser",
        ccache_b64=FAKE_CCACHE_B64, kerberos=True, runner=fake_runner,
    )
    assert len(calls) == 1
    args, kwargs, ccache_contents = calls[0]
    assert "-k" in args[0]
    assert "KRB5CCNAME" in kwargs.get("env", {})
    assert ccache_contents == b"FAKE_CCACHE_BYTES"
