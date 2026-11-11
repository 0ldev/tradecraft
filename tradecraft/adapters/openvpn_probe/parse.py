"""
Pure parsing for openvpn_probe: builds the fixed OpenVPN control-channel
handshake packet and classifies a raw response. No socket I/O -- see
execute.py.

Wire format (OpenVPN's own documented control-channel packet layout):
one byte packs the opcode in its top 5 bits and a key_id in its bottom
3 bits. P_CONTROL_HARD_RESET_CLIENT_V2 (opcode 7) starts a fresh
handshake: 1-byte opcode/key_id, 8-byte session id, 1-byte empty ack
array, 4-byte packet id -- 14 bytes total, no TLS content yet. A real
OpenVPN server replies with P_CONTROL_HARD_RESET_SERVER_V2 (opcode 8).

This is fingerprint-only. It deliberately does not attempt
CVE-2020-15078 (an auth-token username-enumeration oracle, relevant
only when the server uses deferred auth with --auth-gen-token):
confirming it needs a real TLS-over-control-channel exchange and a
crafted auth message, well past the initial handshake this probe
implements.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

OP_HARD_RESET_CLIENT_V2 = 7
OP_HARD_RESET_SERVER_V2 = 8
SESSION_ID_BYTES = 8


def build_hard_reset_client_v2(session_id: bytes) -> bytes:
    """Builds one P_CONTROL_HARD_RESET_CLIENT_V2 packet from an 8-byte
    session id. Always key_id 0 and packet id 0 -- this is always the
    very first packet of a fresh handshake, never a follow-up."""
    if len(session_id) != SESSION_ID_BYTES:
        raise ValueError(f"session_id must be exactly {SESSION_ID_BYTES} bytes")
    opcode_byte = OP_HARD_RESET_CLIENT_V2 << 3  # key_id 0
    ack_array_len = b"\x00"
    packet_id = (0).to_bytes(4, "big")
    return bytes([opcode_byte]) + session_id + ack_array_len + packet_id


def classify_response(data: bytes) -> Dict[str, Any]:
    """Classifies raw response bytes against the control-channel opcode
    only -- deliberately shallow, see module docstring."""
    if not data:
        return {"is_openvpn": False, "note": "no response"}
    opcode = data[0] >> 3
    key_id = data[0] & 0x07
    is_openvpn = opcode == OP_HARD_RESET_SERVER_V2
    return {
        "is_openvpn": is_openvpn,
        "opcode": opcode,
        "key_id": key_id,
        "response_length": len(data),
        "response_hex": data.hex(),
    }


@dataclass
class RawOpenvpnProbeResult:
    target: str = ""
    host: str = ""
    port: int = 0
    protocol: str = "udp"
    response_bytes: bytes = b""
    error: Optional[str] = None


def parse_openvpn_result(raw: RawOpenvpnProbeResult) -> Dict[str, Any]:
    """Turns a raw probe invocation into the model-facing result."""
    base: Dict[str, Any] = {
        "target": raw.target,
        "host": raw.host,
        "port": raw.port,
        "protocol": raw.protocol,
    }
    if raw.error:
        return {**base, "status": "failed", "error": raw.error}

    classification = classify_response(raw.response_bytes)
    status = "fingerprinted" if classification["is_openvpn"] else "no_match"
    result = {**base, "status": status, **classification}
    if classification["is_openvpn"]:
        result["note"] = (
            "OpenVPN control-channel handshake opcode confirmed "
            "(HARD_RESET_SERVER_V2). Fingerprint only -- CVE-2020-15078 "
            "is not tested; see this tool's description for why."
        )
    return result
