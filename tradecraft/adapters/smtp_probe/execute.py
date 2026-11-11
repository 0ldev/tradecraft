"""
Execution logic for SMTP capability probing.
Issues EHLO, interrogates extensions/STARTTLS, and tests VRFY capability safely.
"""
from __future__ import annotations

import re
import socket
import ssl
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


def normalize_host(target: str) -> str:
    """Extracts a bare hostname or IP address from target."""
    raw = target.strip()
    if "://" in raw:
        parsed = urllib.parse.urlsplit(raw)
        host = parsed.hostname or raw
        return host.strip()
    if "/" in raw:
        raw = raw.split("/", 1)[0]
    if ":" in raw:
        if raw.startswith("[") and "]" in raw:
            return raw[1 : raw.index("]")]
        parts = raw.split(":")
        if len(parts) == 2 and parts[1].isdigit():
            return parts[0].strip()
    return raw.strip()


def read_smtp_response(sock: socket.socket, buffer_size: int = 4096) -> Tuple[int, List[str]]:
    """Reads a complete single-line or multi-line SMTP response according to RFC 5321.
    Multi-line responses have lines formatted as 'XYZ-<text>', ending with 'XYZ <text>'.
    """
    lines: List[str] = []
    data_acc = ""
    status_code = 0

    while True:
        chunk = sock.recv(buffer_size)
        if not chunk:
            break
        data_acc += chunk.decode("latin-1", errors="replace")
        while "\r\n" in data_acc or "\n" in data_acc:
            if "\r\n" in data_acc:
                line, data_acc = data_acc.split("\r\n", 1)
            else:
                line, data_acc = data_acc.split("\n", 1)
            line = line.strip()
            if not line:
                continue
            lines.append(line)

            # Check if this line is the terminal line of the response
            # Format: 'XYZ ' or exactly 3 digits
            if len(line) >= 3 and line[:3].isdigit():
                status_code = int(line[:3])
                if len(line) == 3 or line[3] == " ":
                    return status_code, lines
                # If line[3] == '-', multi-line continues
        # If no more chunks expected or newline was terminal
        if lines and status_code != 0 and len(lines[-1]) >= 4 and lines[-1][3] == " ":
            break

    return status_code, lines


@dataclass
class SmtpResult:
    target: str
    host: str
    port: int
    connected: bool = False
    banner: str = ""
    software: Optional[str] = None
    extensions: List[str] = field(default_factory=list)
    starttls_advertised: bool = False
    starttls_active: bool = False
    tls_cipher: Optional[str] = None
    tls_version: Optional[str] = None
    auth_mechanisms: List[str] = field(default_factory=list)
    vrfy_tested: bool = False
    vrfy_target: str = ""
    vrfy_code: int = 0
    vrfy_response: str = ""
    user_enumeration_oracle: bool = False
    rtt_ms: float = 0.0
    error: Optional[str] = None
    note: str = ""


def infer_software(banner: str) -> Optional[str]:
    """Infers mail server implementation and version from banner text."""
    lowered = banner.lower()
    if "exim" in lowered:
        m = re.search(r"exim\s+([0-9\._\-]+)", banner, re.IGNORECASE)
        return f"Exim {m.group(1)}" if m else "Exim"
    if "postfix" in lowered:
        m = re.search(r"postfix\s*(\([^\)]+\))?", banner, re.IGNORECASE)
        return m.group(0) if m else "Postfix"
    if "sendmail" in lowered:
        m = re.search(r"sendmail\s+([0-9\._\-]+)", banner, re.IGNORECASE)
        return f"Sendmail {m.group(1)}" if m else "Sendmail"
    if "microsoft esmtp mail service" in lowered or "exchange" in lowered:
        return "Microsoft Exchange"
    if "dovecot" in lowered:
        return "Dovecot"
    return None


def execute(
    target: str,
    port: int = 25,
    starttls: bool = True,
    vrfy_target: str = "root",
    timeout: int = 5,
) -> SmtpResult:
    """Probes SMTP capabilities on target."""
    host = normalize_host(target)
    if not host:
        return SmtpResult(
            target=target,
            host=host,
            port=port,
            error=f"Invalid target: '{target}'",
        )

    effective_timeout = max(1.0, min(float(timeout), 10.0))

    # Candidate ports: if default 25 was requested, allow fallback to 587 if 25 drops
    ports_to_try = [port]
    if port == 25:
        ports_to_try.append(587)

    raw_sock: Optional[socket.socket] = None
    active_port = port
    last_err: Optional[str] = None

    t0 = time.perf_counter()

    for p in ports_to_try:
        active_port = p
        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.settimeout(effective_timeout)

            # If port 465 (implicit TLS), wrap before connect
            if active_port == 465:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn_sock = ctx.wrap_socket(raw_sock, server_hostname=host)
            else:
                conn_sock = raw_sock

            conn_sock.connect((host, active_port))
            break
        except (socket.timeout, TimeoutError) as exc:
            last_err = f"Connection to {host}:{active_port} timed out after {effective_timeout:.1f}s"
            if raw_sock:
                raw_sock.close()
                raw_sock = None
        except ConnectionRefusedError as exc:
            last_err = f"Connection refused on {host}:{active_port}"
            if raw_sock:
                raw_sock.close()
                raw_sock = None
        except Exception as exc:
            last_err = str(exc)
            if raw_sock:
                raw_sock.close()
                raw_sock = None

    if not raw_sock:
        return SmtpResult(
            target=target,
            host=host,
            port=active_port,
            connected=False,
            error=last_err or "Failed to connect to SMTP service",
        )

    try:
        b_code, b_lines = read_smtp_response(conn_sock)
        banner_text = " ".join(b_lines).strip()
        software = infer_software(banner_text)

        # Send EHLO
        conn_sock.sendall(b"EHLO tradecraft.local\r\n")
        e_code, e_lines = read_smtp_response(conn_sock)

        if e_code != 250:
            # Fallback to HELO
            conn_sock.sendall(b"HELO tradecraft.local\r\n")
            e_code, e_lines = read_smtp_response(conn_sock)

        extensions: List[str] = []
        auth_mechanisms: List[str] = []
        starttls_advertised = False

        for l in e_lines:
            ext = l[4:].strip() if len(l) > 4 else l
            if not ext:
                continue
            extensions.append(ext)
            ext_upper = ext.upper()
            if "STARTTLS" in ext_upper:
                starttls_advertised = True
            if ext_upper.startswith("AUTH"):
                # e.g. AUTH PLAIN LOGIN CRAM-MD5
                parts = ext.split()
                if len(parts) > 1:
                    auth_mechanisms.extend(parts[1:])

        starttls_active = False
        tls_cipher = None
        tls_version = None

        # Issue STARTTLS if advertised and requested
        if starttls and starttls_advertised and active_port != 465:
            conn_sock.sendall(b"STARTTLS\r\n")
            s_code, s_lines = read_smtp_response(conn_sock)
            if s_code == 220:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                tls_sock = ctx.wrap_socket(conn_sock, server_hostname=host)
                conn_sock = tls_sock
                starttls_active = True
                try:
                    cipher_info = tls_sock.cipher()
                    if cipher_info:
                        tls_cipher = cipher_info[0]
                    tls_version = tls_sock.version()
                except Exception:
                    pass
                # Re-issue EHLO over TLS
                conn_sock.sendall(b"EHLO tradecraft.local\r\n")
                _, post_lines = read_smtp_response(conn_sock)
                for l in post_lines:
                    ext = l[4:].strip() if len(l) > 4 else l
                    if ext.upper().startswith("AUTH"):
                        parts = ext.split()
                        if len(parts) > 1:
                            for m in parts[1:]:
                                if m not in auth_mechanisms:
                                    auth_mechanisms.append(m)

        # Test VRFY user enumeration
        vrfy_tested = False
        vrfy_code = 0
        vrfy_response = ""
        user_enum_oracle = False

        if vrfy_target:
            vrfy_tested = True
            v_probe = vrfy_target.strip()
            # If no domain, attach host domain
            if "@" not in v_probe:
                v_probe = f"{v_probe}@{host}"
            conn_sock.sendall(f"VRFY {v_probe}\r\n".encode("latin-1"))
            vrfy_code, vrfy_lines = read_smtp_response(conn_sock)
            vrfy_response = " ".join(vrfy_lines).strip()

            # Analyze VRFY code
            # 250 / 251: User verified (oracle positive!)
            # 550 / 551 / 553: User unknown (oracle leaks absence!)
            if vrfy_code in (250, 251):
                user_enum_oracle = True
            elif vrfy_code in (550, 551, 553):
                user_enum_oracle = True
            # 252 or 502: Administrative prohibition / VRFY disabled (no oracle)

        try:
            conn_sock.sendall(b"QUIT\r\n")
        except Exception:
            pass

        rtt = (time.perf_counter() - t0) * 1000.0

        return SmtpResult(
            target=target,
            host=host,
            port=active_port,
            connected=True,
            banner=banner_text,
            software=software,
            extensions=extensions,
            starttls_advertised=starttls_advertised,
            starttls_active=starttls_active,
            tls_cipher=tls_cipher,
            tls_version=tls_version,
            auth_mechanisms=auth_mechanisms,
            vrfy_tested=vrfy_tested,
            vrfy_target=vrfy_target,
            vrfy_code=vrfy_code,
            vrfy_response=vrfy_response,
            user_enumeration_oracle=user_enum_oracle,
            rtt_ms=round(rtt, 2),
        )

    except Exception as exc:
        return SmtpResult(
            target=target,
            host=host,
            port=active_port,
            connected=True,
            error=str(exc),
        )
    finally:
        try:
            conn_sock.close()
        except Exception:
            pass
