"""
openvpn_probe adapter package.
"""
from tradecraft.adapters.openvpn_probe.execute import execute
from tradecraft.adapters.openvpn_probe.parse import parse_openvpn_result

__all__ = ["execute", "parse_openvpn_result"]
