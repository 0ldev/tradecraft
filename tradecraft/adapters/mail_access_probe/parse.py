"""
Parsing and security audit logic for mail_access_probe.
Pure functions -- no I/O, no subprocess, no network.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from tradecraft.adapters.mail_access_probe.execute import RawMailAccessResult


def infer_software(banner: str) -> Optional[str]:
    """Infers mail access server software and version from banner text."""
    lowered = (banner or "").lower()
    if "dovecot" in lowered:
        m = re.search(r"dovecot\s+([0-9\._\-]+)", banner, re.IGNORECASE)
        return f"Dovecot {m.group(1)}" if m else "Dovecot"
    if "courier" in lowered:
        m = re.search(r"courier(?:-[a-z]+)?\s+([0-9\._\-]+)", banner, re.IGNORECASE)
        return f"Courier {m.group(1)}" if m else "Courier"
    if "cyrus" in lowered:
        m = re.search(r"cyrus(?:\s+[a-z0-9]+)*\s+v?([0-9\._\-]+)", banner, re.IGNORECASE)
        return f"Cyrus {m.group(1)}" if m else "Cyrus"
    if "microsoft" in lowered or "exchange" in lowered:
        return "Microsoft Exchange"
    if "zimbra" in lowered:
        return "Zimbra"
    return None


def extract_auth_mechanisms(protocol: str, capabilities: List[str]) -> List[str]:
    """Extracts SASL or authentication mechanisms from capabilities."""
    mechanisms: List[str] = []
    if protocol == "imap":
        for cap in capabilities:
            cap_u = cap.upper()
            if cap_u.startswith("AUTH="):
                mech = cap[len("AUTH="):].strip()
                if mech and mech not in mechanisms:
                    mechanisms.append(mech)
    else:  # pop3
        for cap in capabilities:
            cap_u = cap.upper()
            if cap_u.startswith("SASL"):
                parts = cap.split()
                if len(parts) > 1:
                    for m in parts[1:]:
                        m_clean = m.strip().upper()
                        if m_clean and m_clean not in mechanisms:
                            mechanisms.append(m_clean)
    return mechanisms


def evaluate_cleartext_auth(
    protocol: str,
    is_tls: bool,
    capabilities: List[str],
) -> Tuple[bool, Optional[str]]:
    """Evaluates whether unencrypted credentials can be sent over plaintext."""
    if is_tls:
        return False, None

    caps_upper = [c.upper() for c in capabilities]

    if protocol == "imap":
        has_login_disabled = "LOGINDISABLED" in caps_upper
        auth_mechs = [c[len("AUTH="):].strip().upper() for c in caps_upper if c.startswith("AUTH=")]
        has_plain_auth = any(m in ("PLAIN", "LOGIN") for m in auth_mechs)

        if not has_login_disabled:
            return (
                True,
                "IMAP server permits plaintext LOGIN authentication over an unencrypted channel without TLS (RFC 3501 violation).",
            )
        if has_plain_auth:
            return (
                True,
                f"IMAP server advertises plaintext SASL mechanisms ({', '.join(auth_mechs)}) over an unencrypted channel without TLS.",
            )
        return False, None

    else:  # pop3
        has_user_cmd = any(c == "USER" for c in caps_upper) or not caps_upper
        sasl_mechs = []
        for c in caps_upper:
            if c.startswith("SASL"):
                parts = c.split()
                if len(parts) > 1:
                    sasl_mechs.extend(parts[1:])
        has_plain_sasl = any(m in ("PLAIN", "LOGIN") for m in sasl_mechs)

        if has_user_cmd or has_plain_sasl:
            return (
                True,
                "POP3 server permits plaintext USER/PASS authentication over an unencrypted channel without TLS (RFC 1939 violation).",
            )
        return False, None


def parse_result(raw: RawMailAccessResult) -> Dict[str, Any]:
    if raw.error and not raw.connected:
        return {
            "target": raw.target,
            "host": raw.host,
            "port": raw.port,
            "protocol": raw.protocol,
            "connected": False,
            "error": raw.error,
        }

    software = infer_software(raw.banner)
    effective_caps = raw.capabilities_post_tls if raw.is_tls else raw.capabilities_pre_tls
    auth_mechs = extract_auth_mechanisms(raw.protocol, effective_caps)

    # For cleartext auth audit, evaluate pre-TLS capabilities if plaintext
    pre_auth_caps = raw.capabilities_pre_tls if not raw.implicit_tls else []
    cleartext_allowed, cleartext_reason = evaluate_cleartext_auth(
        protocol=raw.protocol,
        is_tls=raw.is_tls and not raw.starttls_active,  # if upgraded via STARTTLS, pre-TLS was plaintext!
        capabilities=pre_auth_caps if not raw.implicit_tls else effective_caps,
    )

    tls_mode = "plaintext"
    if raw.implicit_tls:
        tls_mode = "implicit_tls"
    elif raw.starttls_active:
        tls_mode = "starttls"

    security_audit = {
        "cleartext_auth_allowed": cleartext_allowed,
        "starttls_supported": raw.starttls_advertised or raw.implicit_tls,
        "vulnerability": cleartext_reason if cleartext_allowed else None,
        "severity": "medium" if cleartext_allowed else None,
    }

    return {
        "target": raw.target,
        "host": raw.host,
        "port": raw.port,
        "protocol": raw.protocol,
        "connected": raw.connected,
        "software": software,
        "banner": raw.banner,
        "tls": {
            "active": raw.is_tls,
            "mode": tls_mode,
            "cipher": raw.tls_cipher,
            "version": raw.tls_version,
            "starttls_advertised": raw.starttls_advertised,
        },
        "capabilities": effective_caps,
        "auth_mechanisms": auth_mechs,
        "security_audit": security_audit,
        "rtt_ms": raw.rtt_ms,
        **({"warning": raw.error} if raw.error else {}),
    }
