"""
Fingerprints an OpenVPN server via one UDP or TCP control-channel
handshake packet (P_CONTROL_HARD_RESET_CLIENT_V2), checking whether the
response's opcode is the server's own HARD_RESET_SERVER_V2 reply.
Fingerprint only -- does not attempt CVE-2020-15078. Classified as
destructive: false (one well-formed protocol packet, no auth, no
write). Belongs to profiles 'web', 'cloud', and 'ad-network'.
"""
from __future__ import annotations

from typing import Any, Dict

from tradecraft.adapters.openvpn_probe.execute import DEFAULT_PORT
from tradecraft.adapters.openvpn_probe.execute import execute as ovpn_execute
from tradecraft.adapters.openvpn_probe.parse import parse_openvpn_result
from tradecraft.tools.base import Tool


class OpenvpnProbe(Tool):
    tool_id = "openvpn_probe"

    def run(
        self,
        target: str,
        port: int = DEFAULT_PORT,
        protocol: str = "udp",
        timeout: int = 5,
    ) -> Dict[str, Any]:
        raw = ovpn_execute(target=target, port=port, protocol=protocol, timeout=timeout)
        return parse_openvpn_result(raw)
