"""
Execution logic for raw TCP banner probe.
Performs a single-shot, strict-timeout connection to probe a TCP port.
"""
from __future__ import annotations

import re
import socket
import ssl
import time
import urllib.parse
from dataclasses import dataclass
from typing import Optional


def normalize_host(target: str) -> str:
    """Extracts a bare hostname or IP address from target."""
    raw = target.strip()
    if "://" in raw:
        parsed = urllib.parse.urlsplit(raw)
        host = parsed.hostname or raw
        return host.strip()
    # If contains slash, take everything before slash
    if "/" in raw:
        raw = raw.split("/", 1)[0]
    # If contains port (e.g. host:1001), extract host (handle ipv6 brackets if present)
    if ":" in raw:
        if raw.startswith("[") and "]" in raw:
            return raw[1 : raw.index("]")]
        # If single colon, host:port
        parts = raw.split(":")
        if len(parts) == 2 and parts[1].isdigit():
            return parts[0].strip()
    return raw.strip()


@dataclass
class ProbeResult:
    target: str
    host: str
    port: int
    connected: bool
    ssl_used: bool
    status: str  # "open", "closed_by_peer", "refused", "timeout", "reset", "ssl_error", "dns_error", "error"
    banner_bytes: bytes = b""
    banner_hex: str = ""
    banner_text: str = ""
    rtt_ms: float = 0.0
    error: Optional[str] = None
    note: str = ""


def execute(
    target: str,
    port: int,
    ssl_probe: bool = False,
    send_data: str = "",
    timeout: int = 5,
) -> ProbeResult:
    """Connects to a single TCP port, optionally sends a probe payload,
    and captures the banner/response with strict timeout."""
    host = normalize_host(target)
    if not host:
        return ProbeResult(
            target=target,
            host=host,
            port=port,
            connected=False,
            ssl_used=ssl_probe,
            status="error",
            error=f"Invalid target: '{target}'",
            note="Could not extract valid hostname or IP from target.",
        )

    try:
        port_num = int(port)
        if not (1 <= port_num <= 65535):
            raise ValueError()
    except (ValueError, TypeError):
        return ProbeResult(
            target=target,
            host=host,
            port=0,
            connected=False,
            ssl_used=ssl_probe,
            status="error",
            error=f"Invalid port: '{port}' (must be 1-65535)",
        )

    # Strictly clamp timeout between 1 and 10 seconds
    effective_timeout = max(1.0, min(float(timeout), 10.0))

    t0 = time.perf_counter()
    raw_sock: Optional[socket.socket] = None
    connected = False

    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(effective_timeout)

        conn_sock: socket.socket = raw_sock
        if ssl_probe:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn_sock = ctx.wrap_socket(raw_sock, server_hostname=host)

        conn_sock.connect((host, port_num))
        connected = True
        rtt = (time.perf_counter() - t0) * 1000.0

        if send_data:
            # Decode literal escape sequences like \r and \n if passed as literal string
            payload_str = send_data.encode("utf-8").decode("unicode_escape")
            payload_bytes = payload_str.encode("latin-1", errors="replace")
            conn_sock.sendall(payload_bytes)

        data = conn_sock.recv(4096)
        rtt_total = (time.perf_counter() - t0) * 1000.0

        if not data:
            return ProbeResult(
                target=target,
                host=host,
                port=port_num,
                connected=True,
                ssl_used=ssl_probe,
                status="closed_by_peer",
                rtt_ms=round(rtt, 2),
                note="TCP handshake succeeded, but remote peer closed connection immediately with 0 bytes (typical tcpwrapped or firewalled port).",
            )

        banner_text = data.decode("latin-1", errors="replace").strip()
        banner_hex = data.hex()

        return ProbeResult(
            target=target,
            host=host,
            port=port_num,
            connected=True,
            ssl_used=ssl_probe,
            status="open",
            banner_bytes=data,
            banner_hex=banner_hex,
            banner_text=banner_text,
            rtt_ms=round(rtt_total, 2),
            note=f"Received {len(data)} bytes banner.",
        )

    except ConnectionRefusedError:
        return ProbeResult(
            target=target,
            host=host,
            port=port_num,
            connected=False,
            ssl_used=ssl_probe,
            status="refused",
            rtt_ms=round((time.perf_counter() - t0) * 1000.0, 2),
            error="Connection refused (port closed or filtered with RST).",
        )
    except ConnectionResetError:
        return ProbeResult(
            target=target,
            host=host,
            port=port_num,
            connected=connected,
            ssl_used=ssl_probe,
            status="reset",
            rtt_ms=round((time.perf_counter() - t0) * 1000.0, 2),
            error="Connection reset by peer (TCP RST received during communication).",
            note="Connection was reset by peer, indicating an active firewall, IDS/IPS, or immediate service termination.",
        )
    except (socket.timeout, TimeoutError):
        return ProbeResult(
            target=target,
            host=host,
            port=port_num,
            connected=connected,
            ssl_used=ssl_probe,
            status="timeout",
            rtt_ms=round((time.perf_counter() - t0) * 1000.0, 2),
            error=f"Connection or read timed out after {effective_timeout:.1f}s.",
            note="Host did not respond within timeout (port dropped/filtered or silent service).",
        )
    except ssl.SSLError as exc:
        return ProbeResult(
            target=target,
            host=host,
            port=port_num,
            connected=connected,
            ssl_used=ssl_probe,
            status="ssl_error",
            rtt_ms=round((time.perf_counter() - t0) * 1000.0, 2),
            error=f"SSL/TLS handshake failed: {exc}",
            note="Remote port rejected or failed TLS handshake; port may expect plaintext TCP.",
        )
    except socket.gaierror as exc:
        return ProbeResult(
            target=target,
            host=host,
            port=port_num,
            connected=False,
            ssl_used=ssl_probe,
            status="dns_error",
            error=f"DNS resolution failure for host '{host}': {exc}",
        )
    except Exception as exc:
        return ProbeResult(
            target=target,
            host=host,
            port=port_num,
            connected=connected,
            ssl_used=ssl_probe,
            status="error",
            rtt_ms=round((time.perf_counter() - t0) * 1000.0, 2),
            error=str(exc),
        )
    finally:
        if raw_sock:
            try:
                raw_sock.close()
            except Exception:
                pass
