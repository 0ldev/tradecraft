"""
Raw UDP/TCP socket execution for openvpn_probe: sends one
P_CONTROL_HARD_RESET_CLIENT_V2 packet (built in parse.py) and reads
whatever comes back within a bounded timeout. No parsing/classification
here -- parse.py's job.

A timeout with no response is not treated as an error on either
protocol: silence is the expected, legitimate outcome for a filtered,
closed, or non-OpenVPN service, and parse.py's classify_response()
already turns an empty response into a clean "not OpenVPN" result.
Only a genuine failure (bad input, DNS resolution failure, TCP
connection refused, an unexpected exception) sets `error`.
"""
from __future__ import annotations

import os
import socket
from typing import Optional

from tradecraft.adapters.openvpn_probe import parse as ovpn_parse
from tradecraft.adapters.tcp_probe.execute import normalize_host

DEFAULT_PORT = 1194
MAX_RESPONSE_BYTES = 256
VALID_PROTOCOLS = ("udp", "tcp")


def _read_tcp_response(sock: socket.socket) -> bytes:
    """OpenVPN-over-TCP frames each packet with a 2-byte big-endian
    length prefix ahead of the same control-channel packet format."""
    length_prefix = sock.recv(2)
    if len(length_prefix) < 2:
        return b""
    length = min(int.from_bytes(length_prefix, "big"), MAX_RESPONSE_BYTES)
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            break
        data += chunk
    return data


def execute(
    target: str,
    port: int = DEFAULT_PORT,
    protocol: str = "udp",
    timeout: int = 5,
) -> ovpn_parse.RawOpenvpnProbeResult:
    """Runs exactly one handshake-fingerprint exchange against one
    host:port over UDP or TCP."""
    host = normalize_host(target)
    if not host:
        return ovpn_parse.RawOpenvpnProbeResult(target=target, error=f"invalid target: {target!r}")

    try:
        port_num = int(port)
        if not (1 <= port_num <= 65535):
            raise ValueError
    except (ValueError, TypeError):
        return ovpn_parse.RawOpenvpnProbeResult(
            target=target, host=host, error=f"invalid port: {port!r} (must be 1-65535)"
        )

    proto = (protocol or "udp").strip().lower()
    if proto not in VALID_PROTOCOLS:
        return ovpn_parse.RawOpenvpnProbeResult(
            target=target,
            host=host,
            port=port_num,
            error=f"protocol must be one of: {', '.join(VALID_PROTOCOLS)}",
        )

    effective_timeout = max(1.0, min(float(timeout), 10.0))
    session_id = os.urandom(ovpn_parse.SESSION_ID_BYTES)
    packet = ovpn_parse.build_hard_reset_client_v2(session_id)

    sock: Optional[socket.socket] = None
    try:
        if proto == "udp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(effective_timeout)
            sock.sendto(packet, (host, port_num))
            try:
                data, _ = sock.recvfrom(MAX_RESPONSE_BYTES)
            except socket.timeout:
                data = b""
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(effective_timeout)
            try:
                sock.connect((host, port_num))
            except socket.timeout:
                return ovpn_parse.RawOpenvpnProbeResult(
                    target=target, host=host, port=port_num, protocol=proto, response_bytes=b""
                )
            framed = len(packet).to_bytes(2, "big") + packet
            sock.sendall(framed)
            try:
                data = _read_tcp_response(sock)
            except socket.timeout:
                data = b""

        return ovpn_parse.RawOpenvpnProbeResult(
            target=target, host=host, port=port_num, protocol=proto, response_bytes=data
        )
    except ConnectionRefusedError:
        return ovpn_parse.RawOpenvpnProbeResult(
            target=target,
            host=host,
            port=port_num,
            protocol=proto,
            error="connection refused (TCP port closed)",
        )
    except socket.gaierror as exc:
        return ovpn_parse.RawOpenvpnProbeResult(
            target=target, host=host, port=port_num, protocol=proto, error=f"DNS resolution failed: {exc}"
        )
    except Exception as exc:  # noqa: BLE001 - surfaced to the model as a tool error
        return ovpn_parse.RawOpenvpnProbeResult(
            target=target, host=host, port=port_num, protocol=proto, error=str(exc)
        )
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass
