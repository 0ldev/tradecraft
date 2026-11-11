"""
Parsing and capability analysis for SMTP probe results.
Pure functions, no I/O.
"""
from __future__ import annotations

from typing import Any, Dict, List

from tradecraft.adapters.smtp_probe.execute import SmtpResult


def parse(result: SmtpResult) -> Dict[str, Any]:
    """Formats SmtpResult into a structured dictionary."""
    findings: List[str] = []

    if result.user_enumeration_oracle:
        findings.append(
            f"SMTP VRFY User Enumeration Oracle enabled on {result.host}:{result.port} (code {result.vrfy_code})"
        )

    if not result.starttls_active and result.auth_mechanisms:
        findings.append(
            f"Insecure SMTP Authentication Advertised over Plaintext on {result.host}:{result.port}: {', '.join(result.auth_mechanisms)}"
        )

    output: Dict[str, Any] = {
        "target": result.target,
        "host": result.host,
        "port": result.port,
        "connected": result.connected,
        "software": result.software,
        "banner": result.banner,
        "extensions": result.extensions[:15],
        "starttls": {
            "advertised": result.starttls_advertised,
            "active": result.starttls_active,
            "cipher": result.tls_cipher,
            "version": result.tls_version,
        },
        "auth": {
            "advertised": bool(result.auth_mechanisms),
            "mechanisms": result.auth_mechanisms,
        },
        "vrfy": {
            "tested": result.vrfy_tested,
            "target": result.vrfy_target,
            "code": result.vrfy_code,
            "response": result.vrfy_response,
            "user_enumeration_oracle": result.user_enumeration_oracle,
        },
        "findings": findings,
        "rtt_ms": result.rtt_ms,
    }

    if result.error:
        output["error"] = result.error
    if result.note:
        output["note"] = result.note

    return output
