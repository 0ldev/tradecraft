"""
Parsing and signature analysis for TCP probe output.
Pure functions, no I/O.
"""
from __future__ import annotations

import re
from typing import Any, Dict, Optional

from tradecraft.adapters.tcp_probe.execute import ProbeResult


def identify_service(banner_text: str, banner_bytes: bytes, port: int) -> Optional[str]:
    """Infers high-confidence service protocol from raw banner signatures."""
    if not banner_text and not banner_bytes:
        return None

    lowered = banner_text.lower()

    if banner_text.startswith("SSH-"):
        return "ssh"
    if "http/" in lowered or "<html" in lowered or "bad request" in lowered:
        return "http"
    if banner_text.startswith("220") and ("smtp" in lowered or "esmtp" in lowered or "exim" in lowered or "postfix" in lowered):
        return "smtp"
    if banner_text.startswith("220") and ("ftp" in lowered or "proftpd" in lowered or "vsftpd" in lowered or "pure-ftpd" in lowered):
        return "ftp"
    if "mysql" in lowered or "mariadb" in lowered or b"mysql_native_password" in banner_bytes:
        return "mysql"
    if "+pong" in lowered or "-err" in lowered or "redis" in lowered:
        return "redis"
    if banner_bytes.startswith(b"RFB 00"):
        return "vnc"
    if banner_text.startswith("+OK") and ("pop3" in lowered or "dovecot" in lowered):
        return "pop3"
    if banner_text.startswith("* OK") and ("imap" in lowered or "dovecot" in lowered):
        return "imap"

    # Port heuristic fallbacks if banner confirmed
    if port == 21 and banner_text.startswith("220"):
        return "ftp"
    if port in (25, 587) and banner_text.startswith("220"):
        return "smtp"
    if port == 110 and banner_text.startswith("+OK"):
        return "pop3"
    if port == 143 and banner_text.startswith("* OK"):
        return "imap"

    return None


def sanitize_printable(text: str, max_len: int = 1000) -> str:
    """Cleans control characters while preserving newlines and standard punctuation."""
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]", ".", text)
    if len(cleaned) > max_len:
        return cleaned[:max_len] + f"... [truncated, total {len(cleaned)} chars]"
    return cleaned


def parse(result: ProbeResult) -> Dict[str, Any]:
    """Transforms raw ProbeResult into a structured dictionary suitable for
    both the model's turn context and evidence storage."""
    service = identify_service(result.banner_text, result.banner_bytes, result.port)
    printable_banner = sanitize_printable(result.banner_text)

    output: Dict[str, Any] = {
        "target": result.target,
        "host": result.host,
        "port": result.port,
        "connected": result.connected,
        "ssl": result.ssl_used,
        "status": result.status,
        "service": service,
        "banner": printable_banner,
        "rtt_ms": result.rtt_ms,
    }

    if result.error:
        output["error"] = result.error
    if result.note:
        output["note"] = result.note

    return output
