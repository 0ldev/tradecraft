"""
Execution logic for websocket_security_probe: opens a raw socket (TLS-
wrapped for wss) per Origin value, sends a manual WebSocket upgrade
HTTP request, and reads whether the server replies 101 Switching
Protocols -- a cross-origin Origin that still gets a 101 indicates
missing Origin validation (Cross-Site WebSocket Hijacking risk). No
third-party websocket library -- same raw-socket approach as
http_smuggling_probe. Each connection is closed immediately after the
handshake response is read. No parsing here -- that's parse.py's job.
"""
from __future__ import annotations

import base64
import secrets
import socket
import ssl
import urllib.parse
from dataclasses import dataclass, field
from typing import List, Optional

_MAX_RESPONSE_BYTES = 8192
DEFAULT_ORIGINS = ("same-origin", "https://evil.tradecraft-probe.test")


@dataclass
class RawHandshakeAttempt:
    origin_label: str
    origin_header: str
    status_line: str = ""
    accepted: bool = False
    connected: bool = False
    error: Optional[str] = None


@dataclass
class RawWebsocketProbeRun:
    target: str = ""
    host: str = ""
    port: int = 0
    path: str = ""
    use_tls: bool = False
    attempts: List[RawHandshakeAttempt] = field(default_factory=list)
    error: Optional[str] = None


def _parse_host_port(target: str, default_port: int) -> "tuple[str, int]":
    raw = target.strip()
    if "://" in raw:
        parsed = urllib.parse.urlsplit(raw)
        return parsed.hostname or "", (parsed.port or default_port)
    if raw.startswith("[") and "]" in raw:
        host = raw[1: raw.index("]")]
        rest = raw[raw.index("]") + 1:]
        port = int(rest[1:]) if rest.startswith(":") else default_port
        return host, port
    if ":" in raw:
        host, _, port_str = raw.rpartition(":")
        if port_str.isdigit():
            return host, int(port_str)
    return raw, default_port


def _build_handshake(host: str, port: int, path: str, origin_header: str, cookie: Optional[str]) -> bytes:
    key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
    host_header = host if port in (80, 443) else f"{host}:{port}"
    lines = [
        f"GET {path} HTTP/1.1",
        f"Host: {host_header}",
        "Upgrade: websocket",
        "Connection: Upgrade",
        f"Sec-WebSocket-Key: {key}",
        "Sec-WebSocket-Version: 13",
        f"Origin: {origin_header}",
    ]
    if cookie:
        lines.append(f"Cookie: {cookie}")
    lines.append("\r\n")
    return "\r\n".join(lines).encode("latin-1")


def _attempt_handshake(
    host: str, port: int, path: str, use_tls: bool,
    origin_label: str, origin_header: str, cookie: Optional[str], timeout: float,
) -> RawHandshakeAttempt:
    result = RawHandshakeAttempt(origin_label=origin_label, origin_header=origin_header)
    sock: Optional[socket.socket] = None
    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(timeout)
        sock = raw_sock
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(raw_sock, server_hostname=host)
        sock.connect((host, port))
        result.connected = True

        payload = _build_handshake(host, port, path, origin_header, cookie)
        sock.sendall(payload)

        buf = bytearray()
        while len(buf) < _MAX_RESPONSE_BYTES:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf.extend(chunk)
            if b"\r\n\r\n" in buf:
                break

        status_line = buf.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
        result.status_line = status_line
        result.accepted = " 101 " in f" {status_line} "
    except (socket.timeout, TimeoutError) as exc:
        result.error = f"Connection or handshake timed out: {exc}"
    except ConnectionRefusedError as exc:
        result.error = f"Connection refused: {exc}"
    except ssl.SSLError as exc:
        result.error = f"SSL/TLS handshake failed: {exc}"
    except socket.gaierror as exc:
        result.error = f"DNS resolution failure for host '{host}': {exc}"
    except Exception as exc:  # noqa: BLE001 - recorded as evidence, not raised
        result.error = f"{type(exc).__name__}: {exc}"
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
    return result


def execute(
    target: str,
    path: str = "/",
    origins_to_test: Optional[str] = None,
    cookie: Optional[str] = None,
    timeout: int = 5,
) -> RawWebsocketProbeRun:
    use_tls = ":443" in target or target.strip().startswith("wss://") or target.strip().startswith("https://")
    host, port = _parse_host_port(target, default_port=443 if use_tls else 80)
    if not host:
        return RawWebsocketProbeRun(target=target, error=f"invalid target: '{target}'")

    effective_timeout = max(1.0, min(float(timeout), 10.0))
    same_origin_header = f"{'https' if use_tls else 'http'}://{host}"

    labels: List[str]
    if origins_to_test:
        labels = [o.strip() for o in origins_to_test.split(",") if o.strip()]
    else:
        labels = list(DEFAULT_ORIGINS)

    attempts: List[RawHandshakeAttempt] = []
    for label in labels[:5]:
        origin_header = same_origin_header if label == "same-origin" else label
        attempts.append(_attempt_handshake(host, port, path, use_tls, label, origin_header, cookie, effective_timeout))

    return RawWebsocketProbeRun(target=target, host=host, port=port, path=path, use_tls=use_tls, attempts=attempts)
