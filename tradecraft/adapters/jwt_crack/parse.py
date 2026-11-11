"""
Pure parsing for jwt_crack: turns the raw crack result into the report the
model sees. No I/O.
"""
from __future__ import annotations

from typing import Any, Dict

from tradecraft.adapters.jwt_crack.execute import RawJwtCrackResult


def parse_jwt_crack_result(raw: RawJwtCrackResult) -> Dict[str, Any]:
    if raw.error:
        return {"jwt": raw.jwt, "error": raw.error}

    if raw.not_hmac:
        if raw.algorithm.startswith(("RS", "ES", "PS")):
            reason = f"algorithm '{raw.algorithm}' is asymmetric, not crackable by HMAC brute force"
        else:
            reason = (
                f"algorithm '{raw.algorithm}' is not an HMAC algorithm "
                "(HS256/HS384/HS512); nothing to brute force"
            )
        return {"jwt": raw.jwt, "algorithm": raw.algorithm, "reason": reason}

    if raw.cracked_secret is None:
        return {
            "jwt": raw.jwt,
            "algorithm": raw.algorithm,
            "attempted": raw.attempted,
            "reason": f"no match among {raw.attempted} candidate secret(s)",
        }

    return {
        "jwt": raw.jwt,
        "algorithm": raw.algorithm,
        "cracked_secret": raw.cracked_secret,
        "attempted": raw.attempted,
    }
