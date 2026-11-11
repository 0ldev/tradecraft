"""
Pure parsing functions for jwt_tool output.
Extracts successful tampering vectors, forged tokens, and vulnerability status.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List

from tradecraft.adapters.jwt_tool.execute import RawJwtToolResult

# Regex to capture forged JWT tokens (three base64url segments separated by dots)
_JWT_REGEX = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*")


def parse_jwt_tool_output(raw: RawJwtToolResult) -> Dict[str, Any]:
    """Parses stdout and stderr from a jwt_tool execution into a structured result."""
    if raw.error:
        return {
            "token": raw.token,
            "target_url": raw.target_url,
            "vulnerable": False,
            "findings": [],
            "forged_tokens": [],
            "error": raw.error,
        }

    text = f"{raw.stdout}\n{raw.stderr}"
    lines = text.splitlines()

    findings: List[Dict[str, Any]] = []
    vulnerable = False

    for line in lines:
        cleaned = line.strip()
        lower = cleaned.lower()
        if not cleaned:
            continue

        # Look for successful status codes or bypass indicators
        # jwt_tool flags successful probes with [+] or [SUCCESS] or HTTP 200 responses
        if any(marker in lower for marker in ("[+]", "[success]", "vulnerable", "status: 200", "code: 200", "accepted")):
            # Skip false positives like usage/banner
            if "jwt_tool" in lower and "version" in lower:
                continue
            findings.append({"indicator": cleaned, "type": "tamper_success"})
            vulnerable = True

        elif "alg: none" in lower or "algorithm: none" in lower:
            findings.append({"indicator": cleaned, "type": "none_algorithm"})

        elif "key confusion" in lower or "rs/hs confusion" in lower:
            findings.append({"indicator": cleaned, "type": "key_confusion"})

        elif "kid injection" in lower or "jwks injection" in lower:
            findings.append({"indicator": cleaned, "type": "header_injection"})

    all_tokens = _JWT_REGEX.findall(raw.stdout)
    # Deduplicate while preserving order, excluding original token
    seen = set()
    forged_tokens: List[str] = []
    for tok in all_tokens:
        if tok != raw.token and tok not in seen:
            seen.add(tok)
            forged_tokens.append(tok)

    # If status code 200 or accepted indicator seen, mark confirmed
    return {
        "token": raw.token,
        "target_url": raw.target_url,
        "vulnerable": vulnerable,
        "total_findings": len(findings),
        "findings": findings[:10],
        "forged_tokens": forged_tokens[:5],
    }
