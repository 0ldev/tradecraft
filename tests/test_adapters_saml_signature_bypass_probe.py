"""Unit tests for saml_signature_bypass_probe adapter. Mocks requests.post."""
from __future__ import annotations

import base64
from unittest.mock import MagicMock, patch

from tradecraft.adapters.saml_signature_bypass_probe.execute import (
    ALL_MUTATIONS,
    _comment_injection_nameid,
    _strip_signature,
    _xml_signature_wrapping,
    execute,
)
from tradecraft.adapters.saml_signature_bypass_probe.parse import parse

SAML_XML = b"""<?xml version="1.0"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml2:Assertion>
    <saml2:Subject>
      <saml2:NameID>alice@example.com</saml2:NameID>
    </saml2:Subject>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:SignedInfo>fake</ds:SignedInfo>
    </ds:Signature>
  </saml2:Assertion>
</saml2p:Response>"""

SAML_RESPONSE_B64 = base64.b64encode(SAML_XML).decode("ascii")


def _mock_response(status_code=200, location="", set_cookie=False, text=""):
    resp = MagicMock()
    resp.status_code = status_code
    headers = {}
    if location:
        headers["location"] = location
    if set_cookie:
        headers["set-cookie"] = "session=abc123"
    resp.headers = headers
    resp.text = text
    return resp


def test_strip_signature_removes_signature_element():
    mutated = _strip_signature(SAML_XML)
    assert b"<ds:Signature" not in mutated
    assert b"alice@example.com" in mutated


def test_xml_signature_wrapping_duplicates_assertion_with_admin_nameid():
    mutated = _xml_signature_wrapping(SAML_XML)
    assert mutated.count(b"<saml2:Assertion>") == 2
    assert b">admin<" in mutated
    assert b"alice@example.com" in mutated  # original still present


def test_comment_injection_nameid_inserts_comment():
    mutated = _comment_injection_nameid(SAML_XML)
    assert b"admin<!---->@evil-tradecraft-probe.test" in mutated


def test_execute_rejects_invalid_base64():
    result = execute(target="https://app.example.com/saml/acs", saml_response="not-valid-base64!!!")
    assert result.error is not None


def test_execute_rejects_malformed_xml():
    bad_xml_b64 = base64.b64encode(b"<not><closed>").decode("ascii")
    result = execute(target="https://app.example.com/saml/acs", saml_response=bad_xml_b64)
    assert result.error is not None


def test_execute_sends_all_three_mutations():
    with patch("tradecraft.adapters.saml_signature_bypass_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.post.return_value = _mock_response(status_code=403, text="invalid signature")
        result = execute(target="https://app.example.com/saml/acs", saml_response=SAML_RESPONSE_B64)
    assert result.error is None
    assert {a.mutation for a in result.attempts} == set(ALL_MUTATIONS)


def test_parse_flags_accepted_on_session_cookie():
    with patch("tradecraft.adapters.saml_signature_bypass_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.post.return_value = _mock_response(status_code=200, set_cookie=True, text="welcome")
        raw = execute(target="https://app.example.com/saml/acs", saml_response=SAML_RESPONSE_B64)
    result = parse(raw)
    assert result["vulnerable"] is True
    assert len(result["accepted_mutations"]) == 3


def test_parse_rejected_on_error_message():
    with patch("tradecraft.adapters.saml_signature_bypass_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.post.return_value = _mock_response(status_code=403, text="Invalid signature")
        raw = execute(target="https://app.example.com/saml/acs", saml_response=SAML_RESPONSE_B64)
    result = parse(raw)
    assert result["vulnerable"] is False
    assert all(a["classification"] == "rejected" for a in result["attempts"])
