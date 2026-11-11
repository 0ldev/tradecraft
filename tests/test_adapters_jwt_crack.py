import base64
import hashlib
import hmac
import json
from unittest.mock import patch

from tradecraft.adapters.jwt_crack.execute import (
    MAX_WORDLIST_ENTRIES,
    _BUNDLED_WORDLIST,
    _load_candidates,
    execute,
)
from tradecraft.adapters.jwt_crack.parse import parse_jwt_crack_result

# Canonical jwt.io sample: HS256, signed with "your-256-bit-secret".
JWTIO_TOKEN = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _sign(alg: str, secret: str, payload: dict) -> str:
    hash_fn = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[alg]
    header = _b64(json.dumps({"alg": alg, "typ": "JWT"}, separators=(",", ":")).encode())
    body = _b64(json.dumps(payload, separators=(",", ":")).encode())
    sig = hmac.new(secret.encode(), f"{header}.{body}".encode(), hash_fn).digest()
    return f"{header}.{body}.{_b64(sig)}"


def _no_network(*args, **kwargs):
    raise AssertionError("jwt_crack must never touch the network")


# --- bundled wordlist ---------------------------------------------------------

def test_bundled_wordlist_is_present_and_about_200_entries():
    assert _BUNDLED_WORDLIST.is_file()
    cands = _load_candidates("")
    assert 200 <= len(cands) <= 300
    assert "your-256-bit-secret" in cands
    assert "secret" in cands
    assert all(c == c.strip() and c for c in cands)


# --- execute: cracking -------------------------------------------------------

def test_cracks_canonical_jwtio_token_from_bundled_list():
    with patch("requests.get", side_effect=_no_network), patch("requests.post", side_effect=_no_network):
        raw = execute(JWTIO_TOKEN)
    assert raw.error is None
    assert raw.algorithm == "HS256"
    assert raw.cracked_secret == "your-256-bit-secret"
    assert raw.attempted == _load_candidates("").index("your-256-bit-secret") + 1


def test_cracks_hs512_with_custom_wordlist_and_counts_attempts():
    token = _sign("HS512", "hunter-but-not-in-builtin", {"sub": "admin", "role": "admin"})
    wordlist = "\n\nchangeme\n  \nfoo\nhunter-but-not-in-builtin\nzzz\n"
    raw = execute(token, wordlist=wordlist)
    assert raw.algorithm == "HS512"
    assert raw.cracked_secret == "hunter-but-not-in-builtin"
    assert raw.attempted == 3  # blank lines dropped; stops at the match


def test_cracks_hs384():
    token = _sign("HS384", "devkey", {"uid": 7})
    raw = execute(token, wordlist="a\nb\ndevkey\n")
    assert raw.algorithm == "HS384"
    assert raw.cracked_secret == "devkey"


def test_no_match_reports_attempt_count_via_parse():
    token = _sign("HS256", "a-very-long-random-secret-9f8e7d", {"sub": "1"})
    raw = execute(token, wordlist="one\ntwo\nthree")
    assert raw.cracked_secret is None
    assert raw.attempted == 3
    assert parse_jwt_crack_result(raw) == {
        "jwt": token,
        "algorithm": "HS256",
        "attempted": 3,
        "reason": "no match among 3 candidate secret(s)",
    }


def test_wordlist_is_capped_at_10000_entries():
    secret_past_cap = "needle-at-10001"
    lines = [f"wrong-{i}" for i in range(MAX_WORDLIST_ENTRIES)] + [secret_past_cap]
    token = _sign("HS256", secret_past_cap, {"sub": "x"})
    raw = execute(token, wordlist="\n".join(lines))
    assert raw.cracked_secret is None
    assert raw.attempted == MAX_WORDLIST_ENTRIES


# --- execute: non-HMAC and malformed tokens ----------------------------------

def test_rs256_is_reported_as_not_hmac_without_trying_secrets():
    header = _b64(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    token = f"{header}.{_b64(b'{}')}.{_b64(b'sig')}"
    raw = execute(token)
    assert raw.not_hmac is True
    assert raw.attempted == 0
    assert parse_jwt_crack_result(raw) == {
        "jwt": token,
        "algorithm": "RS256",
        "reason": "algorithm 'RS256' is asymmetric, not crackable by HMAC brute force",
    }


def test_alg_none_is_reported_as_not_hmac():
    header = _b64(json.dumps({"alg": "none"}).encode())
    token = f"{header}.{_b64(b'{}')}."
    out = parse_jwt_crack_result(execute(token))
    assert out["algorithm"] == "none"
    assert "not an HMAC algorithm" in out["reason"]


def test_wrong_segment_count_is_error():
    raw = execute("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0")
    assert raw.error == "not a valid JWT (expected header.payload.signature)"
    assert parse_jwt_crack_result(raw) == {
        "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0",
        "error": "not a valid JWT (expected header.payload.signature)",
    }


def test_undecodable_header_is_error():
    raw = execute("!!!.eyJzdWIiOiIxIn0.c2ln")
    assert raw.error == "JWT header is not valid base64url JSON"


def test_header_without_alg_is_error():
    header = _b64(json.dumps({"typ": "JWT"}).encode())
    raw = execute(f"{header}.{_b64(b'{}')}.{_b64(b'sig')}")
    assert raw.error == "JWT header is not valid base64url JSON"


def test_no_network_calls_are_made():
    with patch("requests.get", side_effect=_no_network), patch("requests.post", side_effect=_no_network):
        execute(_sign("HS256", "changeme", {"a": 1}))
