"""
Raw execution for jwt_crack: offline HMAC secret brute force. Makes no network
calls. Recomputes the HS256/HS384/HS512 signature of the token's own signing
input for each candidate secret and compares it to the token's signature.
No parsing beyond decoding the token itself -- parse.py's job.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

MAX_WORDLIST_ENTRIES = 10_000

_BUNDLED_WORDLIST = Path(__file__).resolve().parent / "common_secrets.txt"

HASH_FUNCS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}


@dataclass
class RawJwtCrackResult:
    jwt: str = ""
    algorithm: str = ""
    attempted: int = 0
    cracked_secret: Optional[str] = None
    not_hmac: bool = False
    error: Optional[str] = None


def _b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _load_candidates(wordlist: str) -> List[str]:
    if wordlist:
        lines = wordlist.splitlines()
    else:
        lines = _BUNDLED_WORDLIST.read_text(encoding="utf-8").splitlines()
    candidates = [line.strip() for line in lines if line.strip()]
    return candidates[:MAX_WORDLIST_ENTRIES]


def execute(jwt: str, wordlist: str = "") -> RawJwtCrackResult:
    token = jwt.strip()
    parts = token.split(".")
    if len(parts) != 3:
        return RawJwtCrackResult(jwt=jwt, error="not a valid JWT (expected header.payload.signature)")
    header_b64, payload_b64, signature_b64 = parts

    try:
        header = json.loads(_b64url_decode(header_b64))
        alg = header["alg"]
    except (ValueError, binascii.Error, TypeError, KeyError):
        return RawJwtCrackResult(jwt=jwt, error="JWT header is not valid base64url JSON")
    if not isinstance(alg, str):
        return RawJwtCrackResult(jwt=jwt, error="JWT header is not valid base64url JSON")

    if alg not in HASH_FUNCS:
        # Asymmetric (RS/ES/PS) or none: not crackable by HMAC brute force.
        return RawJwtCrackResult(jwt=jwt, algorithm=alg, not_hmac=True)

    try:
        target_sig = _b64url_decode(signature_b64)
    except (ValueError, binascii.Error):
        return RawJwtCrackResult(jwt=jwt, algorithm=alg, error="JWT signature is not valid base64url")

    hash_fn = HASH_FUNCS[alg]
    signing_input = f"{header_b64}.{payload_b64}".encode()

    result = RawJwtCrackResult(jwt=jwt, algorithm=alg)
    for candidate in _load_candidates(wordlist):
        result.attempted += 1
        computed = hmac.new(candidate.encode(), signing_input, hash_fn).digest()
        if hmac.compare_digest(computed, target_sig):
            result.cracked_secret = candidate
            break
    return result
