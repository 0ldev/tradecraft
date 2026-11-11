"""
Unit tests for the certipy_enum adapter, parser, Tool wrapper, and
contract.

No domain controller or AD CS deployment is available in the lab, so the
successful-enumeration JSON fixture is constructed from the exact schema
in Certipy 4.8.2's installed source
(``certipy.commands.find.Find.get_output_for_text_and_json`` and its
``get_template_properties`` / ``get_ca_properties`` maps), not presented
as a captured run. The failure fixture IS verbatim captured stdout/stderr
from ``certipy find`` against a non-DC lab host.
"""
from __future__ import annotations

import json
import os
import subprocess
from types import SimpleNamespace

import pytest

from tradecraft.adapters.certipy_enum import execute as ce_execute
from tradecraft.adapters.certipy_enum import parse as ce_parse
from tradecraft.tools.certipy_enum import CertipyEnum
from tradecraft.tools.profiles import load_profile

# REAL: certipy find -u test@corp.local -p <redacted> -dc-ip 192.168.15.23
# -target 192.168.15.23 -json -output /tmp/certipy_probe -timeout 8
# Connection refused -> no JSON file, exit code 0. Certipy logs the error
# on stdout; the version banner and pkg_resources warning go to stderr.
REAL_ERROR_STDOUT = """\
[-] Got error: socket connection error while opening: [Errno 111] Connection refused
[-] Use -debug to print a stacktrace
"""

REAL_ERROR_STDERR = """\
/root/.local/pipx/venvs/certipy-ad/lib/python3.11/site-packages/certipy/version.py:1: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Certipy v4.8.2 - by Oliver Lyak (ly4k)

"""


def _success_data():
    return {
        "Certificate Authorities": {
            "0": {
                "CA Name": "CORP-CA",
                "DNS Name": "dc01.corp.local",
                "Certificate Subject": "CN=CORP-CA, DC=corp, DC=local",
                "Certificate Serial Number": "112233445566778899AABBCCDDEEFF00",
                "Certificate Validity Start": "2024-01-01 00:00:00+00:00",
                "Certificate Validity End": "2034-01-01 00:00:00+00:00",
                "Web Enrollment": "Enabled",
                "User Specified SAN": "Enabled",
                "Request Disposition": "Issue",
                "Enforce Encryption for Requests": "Disabled",
                "Permissions": {
                    "Owner": "CORP\\Domain Admins",
                    "Access Rights": {"ManageCa": ["CORP\\Domain Admins"]},
                },
                "[!] Vulnerabilities": {
                    "ESC7": "CORP\\Domain Admins has dangerous permissions",
                    "ESC8": "Web Enrollment is enabled and Request Disposition is set to Issue",
                    "ESC11": "Encryption is not enforced for ICPR requests and Request Disposition is set to Issue",
                },
            }
        },
        "Certificate Templates": {
            "0": {
                "Template Name": "VulnUser",
                "Display Name": "VulnUser",
                "Certificate Authorities": ["CORP-CA"],
                "Enabled": True,
                "Client Authentication": True,
                "Enrollment Agent": False,
                "Any Purpose": False,
                "Enrollee Supplies Subject": True,
                "Certificate Name Flag": ["EnrolleeSuppliesSubject"],
                "Enrollment Flag": [],
                "Private Key Flag": [],
                "Extended Key Usage": ["Client Authentication"],
                "Requires Manager Approval": False,
                "Requires Key Archival": False,
                "Authorized Signatures Required": 0,
                "Validity Period": "1 year",
                "Renewal Period": "6 weeks",
                "Minimum RSA Key Length": 2048,
                "Permissions": {
                    "Enrollment Permissions": {
                        "Enrollment Rights": ["CORP\\Domain Users"]
                    }
                },
                "[!] Vulnerabilities": {
                    "ESC1": "CORP\\Domain Users can enroll, enrollee supplies subject and template allows client authentication"
                },
            },
            "1": {
                "Template Name": "User",
                "Display Name": "User",
                "Certificate Authorities": ["CORP-CA"],
                "Enabled": True,
                "Client Authentication": True,
                "Enrollee Supplies Subject": False,
                "Requires Manager Approval": False,
                "Authorized Signatures Required": 0,
            },
            "2": {
                "Template Name": "LegacyDisabled",
                "Display Name": "LegacyDisabled",
                "Enabled": False,
                "Client Authentication": False,
                "Enrollee Supplies Subject": False,
            },
        },
    }


CERTIPY_JSON = json.dumps(_success_data(), indent=2)


def test_parse_success_counts_and_entries():
    parsed = ce_parse.parse_certipy_json(CERTIPY_JSON)

    assert parsed["status"] == "success"
    assert parsed["ca_count"] == 1
    assert parsed["template_count"] == 3
    assert parsed["enabled_template_count"] == 2
    assert parsed["vulnerable_ca_count"] == 1
    assert parsed["vulnerable_template_count"] == 1
    assert parsed["cas_truncated"] is False
    assert parsed["templates_truncated"] is False

    ca = parsed["certificate_authorities"][0]
    assert ca["CA Name"] == "CORP-CA"
    assert ca["Permissions"]["Owner"] == "CORP\\Domain Admins"
    assert ca["Web Enrollment"] == "Enabled"

    template = parsed["certificate_templates"][0]
    assert template["Template Name"] == "VulnUser"
    assert template["Enrollee Supplies Subject"] is True
    assert template["[!] Vulnerabilities"]["ESC1"]

    assert parsed["vulnerable_certificate_templates"] == [
        {"name": "VulnUser", "vulnerabilities": ["ESC1"]}
    ]
    assert parsed["vulnerable_certificate_authorities"][0]["name"] == "CORP-CA"
    assert parsed["vulnerable_certificate_authorities"][0][
        "vulnerabilities"
    ] == ["ESC11", "ESC7", "ESC8"]


def test_parse_empty_sections_are_a_success_with_notes():
    data = {
        "Certificate Authorities": "[!] Could not find any CAs",
        "Certificate Templates": (
            "[!] Could not find any certificate templates"
        ),
    }
    parsed = ce_parse.parse_certipy_json(json.dumps(data))

    assert parsed["status"] == "success"
    assert parsed["ca_count"] == 0
    assert parsed["template_count"] == 0
    assert len(parsed["notes"]) == 2
    assert "Could not find any CAs" in parsed["notes"][0]
    assert "Could not find any certificate templates" in parsed["notes"][1]


def test_parse_missing_sections():
    parsed = ce_parse.parse_certipy_json("{}")

    assert parsed["status"] == "success"
    assert parsed["ca_count"] == 0
    assert parsed["template_count"] == 0
    assert "No certificate authorities were found." in parsed["notes"]
    assert "No certificate templates were found." in parsed["notes"]


def test_parse_malformed_json_is_failed():
    parsed = ce_parse.parse_certipy_json("{not json")
    assert parsed["status"] == "failed"
    assert "could not parse certipy JSON output" in parsed["error"]


def test_parse_top_level_not_object_is_failed():
    parsed = ce_parse.parse_certipy_json("[]")
    assert parsed["status"] == "failed"
    assert "expected an object" in parsed["error"]


def test_parse_caps_templates_but_keeps_counts():
    data = {
        "Certificate Authorities": {},
        "Certificate Templates": {
            str(index): {
                "Template Name": f"Template{index}",
                "Enabled": True,
            }
            for index in range(150)
        },
    }
    parsed = ce_parse.parse_certipy_json(json.dumps(data))

    assert parsed["template_count"] == 150
    assert parsed["enabled_template_count"] == 150
    assert len(parsed["certificate_templates"]) == (
        ce_parse.MAX_TEMPLATES_RETURNED
    )
    assert parsed["templates_truncated"] is True


def test_extract_error_lines():
    errors = ce_parse.extract_error_lines(REAL_ERROR_STDOUT)
    assert errors == [
        "Got error: socket connection error while opening: "
        "[Errno 111] Connection refused",
        "Use -debug to print a stacktrace",
    ]


def test_parse_result_uses_real_captured_error():
    raw = ce_parse.RawCertipyEnumResult(
        target="192.168.15.23",
        domain="corp.local",
        scheme="ldaps",
        stdout=REAL_ERROR_STDOUT,
        stderr=REAL_ERROR_STDERR,
        returncode=0,
    )
    parsed = ce_parse.parse_certipy_enum_result(raw)

    assert parsed["status"] == "failed"
    assert "socket connection error" in parsed["error"]
    assert parsed["target"] == "192.168.15.23"


def test_parse_result_without_json_or_error_is_failed():
    raw = ce_parse.RawCertipyEnumResult(
        target="10.0.0.5",
        domain="corp.local",
        stdout="",
        stderr="Certipy v4.8.2 - by Oliver Lyak (ly4k)\n",
        returncode=0,
    )
    parsed = ce_parse.parse_certipy_enum_result(raw)
    assert parsed["status"] == "failed"
    assert "produced no JSON output" in parsed["error"]


def test_parse_result_success_carries_target_and_domain():
    raw = ce_parse.RawCertipyEnumResult(
        target="10.0.0.5",
        domain="corp.local",
        scheme="ldaps",
        json_output=CERTIPY_JSON,
    )
    parsed = ce_parse.parse_certipy_enum_result(raw)
    assert parsed["status"] == "success"
    assert parsed["target"] == "10.0.0.5"
    assert parsed["domain"] == "corp.local"
    assert parsed["scheme"] == "ldaps"


def test_normalize_target_host():
    assert ce_parse.normalize_target_host("10.0.0.5") == "10.0.0.5"
    assert (
        ce_parse.normalize_target_host("ldaps://dc01.corp.local:636")
        == "dc01.corp.local"
    )
    assert ce_parse.normalize_target_host("dc01.corp.local:636") == (
        "dc01.corp.local"
    )
    assert ce_parse.normalize_target_host("   ") == ""


def test_build_argv_all_flags():
    argv = ce_execute.build_argv(
        target="10.0.0.5",
        domain="corp.local",
        username="alice",
        password="Secret",
        dc_ip="10.0.0.5",
        scheme="ldaps",
        enabled_only=True,
        vulnerable_only=True,
        hide_admins=True,
        dc_only=True,
        output_prefix="/tmp/x/certipy",
        binary="/usr/bin/certipy",
    )
    assert argv == [
        "/usr/bin/certipy",
        "find",
        "-json",
        "-output",
        "/tmp/x/certipy",
        "-target",
        "10.0.0.5",
        "-u",
        "alice@corp.local",
        "-timeout",
        "10",
        "-p",
        "Secret",
        "-dc-ip",
        "10.0.0.5",
        "-scheme",
        "ldaps",
        "-enabled",
        "-vulnerable",
        "-hide-admins",
        "-dc-only",
    ]


def test_build_argv_hashes_and_plain_ldap():
    argv = ce_execute.build_argv(
        target="dc01.corp.local",
        domain="corp.local",
        username="alice",
        hashes="LM:NT",
        scheme="ldap",
    )
    assert "-hashes" in argv
    assert argv[argv.index("-hashes") + 1] == "LM:NT"
    assert "-p" not in argv
    assert "-dc-ip" not in argv
    assert argv[argv.index("-scheme") + 1] == "ldap"


@pytest.mark.parametrize(
    "username,expected",
    [
        ("alice", "alice@corp.local"),
        ("alice@corp.local", "alice@corp.local"),
        ("alice@CORP.LOCAL", "alice@corp.local"),
        ("corp.local\\alice", "alice@corp.local"),
    ],
)
def test_normalize_username_forms(username, expected):
    principal, error = ce_execute._normalize_username(
        username, "corp.local"
    )
    assert error is None
    assert principal == expected


def test_normalize_username_rejects_domain_mismatch():
    principal, error = ce_execute._normalize_username(
        "alice@other.local", "corp.local"
    )
    assert principal is None
    assert "does not match" in error

    principal, error = ce_execute._normalize_username(
        "OTHER\\alice", "corp.local"
    )
    assert principal is None
    assert "does not match" in error

    # A NetBIOS short name is not the DNS domain, so it is rejected too.
    principal, error = ce_execute._normalize_username(
        "CORP\\alice", "corp.local"
    )
    assert principal is None
    assert "does not match" in error


def test_build_argv_raises_on_domain_mismatch():
    with pytest.raises(ValueError, match="does not match"):
        ce_execute.build_argv(
            target="10.0.0.5",
            domain="corp.local",
            username="alice@other.local",
            password="pw",
        )


def test_execute_empty_target():
    res = ce_execute.execute(
        target="",
        domain="corp.local",
        username="alice",
        password="pw",
    )
    assert "empty target host" in res.error


def test_execute_rejects_cidr():
    res = ce_execute.execute(
        target="10.0.0.0/24",
        domain="corp.local",
        username="alice",
        password="pw",
    )
    assert "CIDR ranges are not accepted" in res.error


def test_execute_rejects_target_list():
    res = ce_execute.execute(
        target="10.0.0.1,10.0.0.2",
        domain="corp.local",
        username="alice",
        password="pw",
    )
    assert "target lists are not accepted" in res.error


def test_execute_rejects_ip_range():
    res = ce_execute.execute(
        target="10.0.0.1-10.0.0.5",
        domain="corp.local",
        username="alice",
        password="pw",
    )
    assert "IP ranges are not accepted" in res.error


def test_execute_rejects_local_file_target(tmp_path):
    target_file = tmp_path / "targets.txt"
    target_file.write_text("10.0.0.1\n")
    res = ce_execute.execute(
        target=str(target_file),
        domain="corp.local",
        username="alice",
        password="pw",
    )
    assert "local file" in res.error


def test_execute_rejects_missing_domain():
    res = ce_execute.execute(
        target="10.0.0.5",
        domain="",
        username="alice",
        password="pw",
    )
    assert "domain is required" in res.error


def test_execute_rejects_missing_username():
    res = ce_execute.execute(
        target="10.0.0.5",
        domain="corp.local",
        username="",
        password="pw",
    )
    assert "username is required" in res.error


def test_execute_rejects_missing_secret():
    res = ce_execute.execute(
        target="10.0.0.5",
        domain="corp.local",
        username="alice",
    )
    assert "one of password or hashes is required" in res.error


def test_execute_rejects_password_and_hashes_together():
    res = ce_execute.execute(
        target="10.0.0.5",
        domain="corp.local",
        username="alice",
        password="pw",
        hashes="LM:NT",
    )
    assert "at most one" in res.error


def test_execute_rejects_username_domain_mismatch():
    res = ce_execute.execute(
        target="10.0.0.5",
        domain="corp.local",
        username="alice@other.local",
        password="pw",
    )
    assert res.error is not None
    assert "does not match" in res.error


def test_execute_rejects_invalid_dc_ip():
    res = ce_execute.execute(
        target="10.0.0.5",
        domain="corp.local",
        username="alice",
        password="pw",
        dc_ip="not-an-ip",
    )
    assert "is not a single IP address" in res.error


def test_execute_rejects_invalid_scheme():
    res = ce_execute.execute(
        target="10.0.0.5",
        domain="corp.local",
        username="alice",
        password="pw",
        scheme="http",
    )
    assert "unsupported scheme" in res.error


def test_execute_missing_binary(monkeypatch):
    monkeypatch.setattr(ce_execute, "find_certipy_binary", lambda: None)
    res = ce_execute.execute(
        target="10.0.0.5",
        domain="corp.local",
        username="alice",
        password="pw",
    )
    assert "not found on path" in res.error.lower()


def test_execute_timeout(monkeypatch):
    monkeypatch.setattr(
        ce_execute, "find_certipy_binary", lambda: "/usr/bin/certipy"
    )

    def fake_runner(argv, **kwargs):
        raise subprocess.TimeoutExpired(cmd=argv, timeout=5)

    res = ce_execute.execute(
        target="10.0.0.5",
        domain="corp.local",
        username="alice",
        password="pw",
        runner=fake_runner,
    )
    assert "timed out" in res.error.lower()


def test_execute_success_writes_and_reads_json(monkeypatch):
    monkeypatch.setattr(
        ce_execute, "find_certipy_binary", lambda: "/usr/bin/certipy"
    )
    captured = {}

    def fake_runner(argv, **kwargs):
        prefix = argv[argv.index("-output") + 1]
        captured["dir"] = os.path.dirname(prefix)
        with open(ce_execute.output_path_for_prefix(prefix), "w") as handle:
            handle.write(CERTIPY_JSON)
        return SimpleNamespace(
            stdout="[*] Saved JSON output to ...\n",
            stderr=REAL_ERROR_STDERR,
            returncode=0,
        )

    res = ce_execute.execute(
        target="10.0.0.5",
        domain="corp.local",
        username="alice",
        password="pw",
        runner=fake_runner,
    )

    assert res.error is None
    assert res.json_output == CERTIPY_JSON
    assert res.returncode == 0
    # The temporary output directory is always cleaned up.
    assert not os.path.exists(captured["dir"])


def test_execute_failure_has_no_json(monkeypatch):
    monkeypatch.setattr(
        ce_execute, "find_certipy_binary", lambda: "/usr/bin/certipy"
    )

    def fake_runner(argv, **kwargs):
        return SimpleNamespace(
            stdout=REAL_ERROR_STDOUT,
            stderr=REAL_ERROR_STDERR,
            returncode=0,
        )

    res = ce_execute.execute(
        target="192.168.15.23",
        domain="corp.local",
        username="alice",
        password="pw",
        runner=fake_runner,
    )
    assert res.json_output is None

    parsed = ce_parse.parse_certipy_enum_result(res)
    assert parsed["status"] == "failed"
    assert "socket connection error" in parsed["error"]


def test_tool_wrapper_evidence_and_facts(monkeypatch):
    tool = CertipyEnum()
    assert tool.tool_id == "certipy_enum"
    assert tool.destructive is False

    monkeypatch.setattr(
        ce_execute, "find_certipy_binary", lambda: "/usr/bin/certipy"
    )

    def fake_run(argv, **kwargs):
        prefix = argv[argv.index("-output") + 1]
        with open(ce_execute.output_path_for_prefix(prefix), "w") as handle:
            handle.write(CERTIPY_JSON)
        return SimpleNamespace(stdout="", stderr="", returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = tool.run(
        target="10.0.0.5",
        domain="corp.local",
        username="alice",
        password="pw",
    )
    assert result["status"] == "success"
    assert result["ca_count"] == 1
    assert result["template_count"] == 3
    assert result["vulnerable_template_count"] == 1
    assert "_full_evidence" in result

    evidence = tool.extract_evidence({"target": "10.0.0.5"}, result)
    assert evidence is not None
    ev_target, ev_data = evidence
    assert ev_target == "10.0.0.5"
    assert ev_data["domain"] == "corp.local"
    assert json.loads(ev_data["json"])["Certificate Authorities"]["0"][
        "CA Name"
    ] == "CORP-CA"

    result["evidence_id"] = "certipy_enum:10.0.0.5"
    facts = tool.extract_facts({"target": "10.0.0.5"}, result)
    assert len(facts) == 1
    fact = facts[0]
    assert fact["host"] == "10.0.0.5"
    assert fact["port"] == 636
    assert fact["protocol"] == "ldaps"
    assert fact["ad_domain"] == "corp.local"
    assert fact["adcs_enumerated"] is True
    assert fact["adcs_ca_count"] == 1
    assert fact["adcs_template_count"] == 3
    assert fact["adcs_vulnerable_template_count"] == 1
    assert fact["adcs_vulnerable"] is True
    assert fact["evidence"] == "certipy_enum:10.0.0.5"


def test_tool_wrapper_plain_ldap_port_and_no_vulnerabilities(monkeypatch):
    tool = CertipyEnum()
    monkeypatch.setattr(
        ce_execute, "find_certipy_binary", lambda: "/usr/bin/certipy"
    )

    clean_json = json.dumps(
        {
            "Certificate Authorities": {},
            "Certificate Templates": {
                "0": {"Template Name": "User", "Enabled": True}
            },
        }
    )

    def fake_run(argv, **kwargs):
        prefix = argv[argv.index("-output") + 1]
        with open(ce_execute.output_path_for_prefix(prefix), "w") as handle:
            handle.write(clean_json)
        return SimpleNamespace(stdout="", stderr="", returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = tool.run(
        target="10.0.0.5",
        domain="corp.local",
        username="alice",
        password="pw",
        scheme="ldap",
    )
    assert result["status"] == "success"
    assert result["vulnerable_template_count"] == 0

    result["evidence_id"] = "certipy_enum:10.0.0.5"
    fact = tool.extract_facts({"target": "10.0.0.5"}, result)[0]
    assert fact["port"] == 389
    assert fact["protocol"] == "ldap"
    assert "adcs_vulnerable" not in fact


def test_tool_failure_has_no_facts(monkeypatch):
    tool = CertipyEnum()
    monkeypatch.setattr(
        ce_execute, "find_certipy_binary", lambda: "/usr/bin/certipy"
    )

    def fake_run(argv, **kwargs):
        return SimpleNamespace(
            stdout=REAL_ERROR_STDOUT, stderr=REAL_ERROR_STDERR, returncode=0
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = tool.run(
        target="192.168.15.23",
        domain="corp.local",
        username="alice",
        password="pw",
    )
    assert result["status"] == "failed"
    assert tool.extract_facts({"target": "192.168.15.23"}, result) == []
    # The failed transcript is still useful evidence.
    assert tool.extract_evidence({"target": "192.168.15.23"}, result) is not None


def test_tool_is_available(monkeypatch):
    tool = CertipyEnum()
    monkeypatch.setattr(
        ce_execute, "find_certipy_binary", lambda: "/usr/bin/certipy"
    )
    assert tool.is_available() is True

    monkeypatch.setattr(ce_execute, "find_certipy_binary", lambda: None)
    assert tool.is_available() is False


def test_certipy_enum_profile_membership():
    assert "certipy_enum" in load_profile("ad-network")
