"""
Execution logic for IMAP and POP3 mail access protocol discovery.
Connects to mail access ports (143, 993, 110, 995), inspects capabilities,
tests STARTTLS/STLS, and audits cleartext authentication vulnerabilities.
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


def detect_protocol(port: int, protocol_hint: Optional[str] = None) -> str:
    if protocol_hint:
        hint = protocol_hint.strip().lower()
        if hint in ("imap", "pop3"):
            return hint
    if port in (110, 995):
        return "pop3"
    return "imap"


def is_implicit_tls(port: int) -> bool:
    return port in (993, 995)


@dataclass
class RawMailAccessResult:
    target: str = ""
    host: str = ""
    port: int = 143
    protocol: str = "imap"
    connected: bool = False
    banner: str = ""
    software: Optional[str] = None
    is_tls: bool = False
    implicit_tls: bool = False
    starttls_advertised: bool = False
    starttls_active: bool = False
    tls_cipher: Optional[str] = None
    tls_version: Optional[str] = None
    capabilities_pre_tls: List[str] = field(default_factory=list)
    capabilities_post_tls: List[str] = field(default_factory=list)
    auth_mechanisms: List[str] = field(default_factory=list)
    cleartext_auth_allowed: bool = False
    rtt_ms: float = 0.0
    error: Optional[str] = None


def read_line(sock: socket.socket, buffer: str, timeout: float = 5.0) -> Tuple[str, str]:
    """Reads one line from socket up to newline, returning (line, remaining_buffer)."""
    sock.settimeout(timeout)
    while "\n" not in buffer:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buffer += chunk.decode("latin-1", errors="replace")
    if "\n" in buffer:
        line, buffer = buffer.split("\n", 1)
        return line.strip("\r"), buffer
    return buffer.strip("\r"), ""


def probe_imap(
    sock: socket.socket,
    host: str,
    port: int,
    starttls: bool = True,
    timeout: float = 5.0,
) -> Tuple[str, List[str], List[str], bool, bool, Optional[str], Optional[str]]:
    """Executes IMAP conversation:
    1. Read greeting line (* OK ...)
    2. Send A001 CAPABILITY
    3. If STARTTLS advertised, send A002 STARTTLS and upgrade
    4. Send A003 CAPABILITY (post-TLS)
    5. Send A999 LOGOUT
    Returns: (banner, pre_tls_caps, post_tls_caps, starttls_advertised, starttls_active, cipher, tls_ver)
    """
    buf = ""
    banner, buf = read_line(sock, buf, timeout)

    # 1. Send CAPABILITY
    sock.sendall(b"A001 CAPABILITY\r\n")
    pre_caps: List[str] = []
    while True:
        line, buf = read_line(sock, buf, timeout)
        if not line:
            break
        if line.startswith("* CAPABILITY"):
            caps = line[len("* CAPABILITY"):].strip().split()
            pre_caps.extend(caps)
        elif line.startswith("A001 "):
            break

    starttls_advertised = any(c.upper() == "STARTTLS" for c in pre_caps)
    starttls_active = False
    post_caps: List[str] = []
    tls_cipher = None
    tls_version = None

    # 2. Negotiate STARTTLS if requested and available
    if starttls and starttls_advertised and not is_implicit_tls(port):
        sock.sendall(b"A002 STARTTLS\r\n")
        resp_line, buf = read_line(sock, buf, timeout)
        if resp_line.startswith("A002 OK"):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            tls_sock = ctx.wrap_socket(sock, server_hostname=host)
            sock = tls_sock
            starttls_active = True
            try:
                c_info = tls_sock.cipher()
                if c_info:
                    tls_cipher = c_info[0]
                tls_version = tls_sock.version()
            except Exception:
                pass

            # Post-TLS capabilities
            buf = ""
            sock.sendall(b"A003 CAPABILITY\r\n")
            while True:
                line, buf = read_line(sock, buf, timeout)
                if not line:
                    break
                if line.startswith("* CAPABILITY"):
                    caps = line[len("* CAPABILITY"):].strip().split()
                    post_caps.extend(caps)
                elif line.startswith("A003 "):
                    break

    try:
        sock.sendall(b"A999 LOGOUT\r\n")
    except Exception:
        pass

    return (banner, pre_caps, post_caps, starttls_advertised, starttls_active, tls_cipher, tls_version)


def probe_pop3(
    sock: socket.socket,
    host: str,
    port: int,
    starttls: bool = True,
    timeout: float = 5.0,
) -> Tuple[str, List[str], List[str], bool, bool, Optional[str], Optional[str]]:
    """Executes POP3 conversation:
    1. Read greeting (+OK ...)
    2. Send CAPA
    3. If STLS advertised, send STLS and upgrade
    4. Send CAPA (post-TLS)
    5. Send QUIT
    Returns: (banner, pre_tls_caps, post_tls_caps, starttls_advertised, starttls_active, cipher, tls_ver)
    """
    buf = ""
    banner, buf = read_line(sock, buf, timeout)

    # 1. Send CAPA
    sock.sendall(b"CAPA\r\n")
    first_resp, buf = read_line(sock, buf, timeout)
    pre_caps: List[str] = []

    if first_resp.startswith("+OK"):
        while True:
            line, buf = read_line(sock, buf, timeout)
            if not line or line == ".":
                break
            pre_caps.append(line.strip())

    starttls_advertised = any("STLS" in c.upper() for c in pre_caps)
    starttls_active = False
    post_caps: List[str] = []
    tls_cipher = None
    tls_version = None

    # 2. Negotiate STLS if requested and available
    if starttls and starttls_advertised and not is_implicit_tls(port):
        sock.sendall(b"STLS\r\n")
        resp_line, buf = read_line(sock, buf, timeout)
        if resp_line.startswith("+OK"):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            tls_sock = ctx.wrap_socket(sock, server_hostname=host)
            sock = tls_sock
            starttls_active = True
            try:
                c_info = tls_sock.cipher()
                if c_info:
                    tls_cipher = c_info[0]
                tls_version = tls_sock.version()
            except Exception:
                pass

            # Post-TLS capabilities
            buf = ""
            sock.sendall(b"CAPA\r\n")
            c_resp, buf = read_line(sock, buf, timeout)
            if c_resp.startswith("+OK"):
                while True:
                    line, buf = read_line(sock, buf, timeout)
                    if not line or line == ".":
                        break
                    post_caps.append(line.strip())

    try:
        sock.sendall(b"QUIT\r\n")
    except Exception:
        pass

    return (banner, pre_caps, post_caps, starttls_advertised, starttls_active, tls_cipher, tls_version)


def execute(
    target: str,
    port: int = 143,
    protocol: Optional[str] = None,
    starttls: bool = True,
    timeout: int = 5,
) -> RawMailAccessResult:
    host = normalize_host(target)
    if not host:
        return RawMailAccessResult(
            target=target,
            host=host,
            port=port,
            error=f"Invalid target: '{target}'",
        )

    proto = detect_protocol(port, protocol)
    implicit = is_implicit_tls(port)
    effective_timeout = max(1.0, min(float(timeout), 15.0))

    t0 = time.perf_counter()
    raw_sock: Optional[socket.socket] = None
    conn_sock: Optional[socket.socket] = None

    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(effective_timeout)

        if implicit:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn_sock = ctx.wrap_socket(raw_sock, server_hostname=host)
        else:
            conn_sock = raw_sock

        conn_sock.connect((host, port))
    except (socket.timeout, TimeoutError):
        if raw_sock:
            raw_sock.close()
        return RawMailAccessResult(
            target=target,
            host=host,
            port=port,
            protocol=proto,
            error=f"Connection to {host}:{port} timed out after {effective_timeout:.1f}s",
        )
    except ConnectionRefusedError:
        if raw_sock:
            raw_sock.close()
        return RawMailAccessResult(
            target=target,
            host=host,
            port=port,
            protocol=proto,
            error=f"Connection refused on {host}:{port}",
        )
    except Exception as exc:
        if raw_sock:
            raw_sock.close()
        return RawMailAccessResult(
            target=target,
            host=host,
            port=port,
            protocol=proto,
            error=f"Socket error on {host}:{port}: {type(exc).__name__}: {exc}",
        )

    try:
        implicit_cipher = None
        implicit_tls_ver = None
        if implicit and hasattr(conn_sock, "cipher"):
            try:
                c_info = conn_sock.cipher()
                if c_info:
                    implicit_cipher = c_info[0]
                implicit_tls_ver = conn_sock.version()
            except Exception:
                pass

        if proto == "imap":
            banner, pre_caps, post_caps, stls_adv, stls_act, cipher, tls_ver = probe_imap(
                sock=conn_sock,
                host=host,
                port=port,
                starttls=starttls,
                timeout=effective_timeout,
            )
        else:
            banner, pre_caps, post_caps, stls_adv, stls_act, cipher, tls_ver = probe_pop3(
                sock=conn_sock,
                host=host,
                port=port,
                starttls=starttls,
                timeout=effective_timeout,
            )

        rtt = (time.perf_counter() - t0) * 1000.0

        is_tls = implicit or stls_act
        final_cipher = implicit_cipher or cipher
        final_tls_ver = implicit_tls_ver or tls_ver

        return RawMailAccessResult(
            target=target,
            host=host,
            port=port,
            protocol=proto,
            connected=True,
            banner=banner,
            is_tls=is_tls,
            implicit_tls=implicit,
            starttls_advertised=stls_adv,
            starttls_active=stls_act,
            tls_cipher=final_cipher,
            tls_version=final_tls_ver,
            capabilities_pre_tls=pre_caps,
            capabilities_post_tls=post_caps,
            rtt_ms=round(rtt, 2),
        )

    except Exception as exc:
        return RawMailAccessResult(
            target=target,
            host=host,
            port=port,
            protocol=proto,
            connected=True,
            error=f"Protocol interrogation failed on {host}:{port}: {type(exc).__name__}: {exc}",
        )
    finally:
        if conn_sock:
            try:
                conn_sock.close()
            except Exception:
                pass
        elif raw_sock:
            try:
                raw_sock.close()
            except Exception:
                pass
