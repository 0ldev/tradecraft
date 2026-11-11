"""
Unit tests for the openvpn_probe adapter and tool layer. All socket I/O
is mocked.
"""
from __future__ import annotations

import socket
from unittest.mock import MagicMock, patch

import pytest

import tradecraft.adapters.openvpn_probe.parse as ovpn_parse
from tradecraft.adapters.openvpn_probe.execute import execute as ovpn_execute
from tradecraft.tools.openvpn_probe import OpenvpnProbe
from tradecraft.tools.profiles import load_profile
from tradecraft.tools.registry import ALL_TOOLS

SESSION_ID = b"\x01\x02\x03\x04\x05\x06\x07\x08"


# ---------------------------------------------------------------------------
# parse.py: packet construction and response classification
# ---------------------------------------------------------------------------


def test_build_hard_reset_client_v2_shape():
    packet = ovpn_parse.build_hard_reset_client_v2(SESSION_ID)
    assert len(packet) == 14
    assert packet[0] == (7 << 3)  # opcode 7, key_id 0
    assert packet[1:9] == SESSION_ID
    assert packet[9] == 0  # empty ack array
    assert packet[10:14] == b"\x00\x00\x00\x00"  # packet id 0


def test_build_hard_reset_client_v2_rejects_wrong_session_id_length():
    with pytest.raises(ValueError):
        ovpn_parse.build_hard_reset_client_v2(b"short")


def test_classify_response_matches_hard_reset_server_v2():
    # opcode 8, key_id 0 -> 8 << 3 = 0x40
    response = bytes([8 << 3]) + b"\xaa" * 8 + b"\x00" + b"\x00\x00\x00\x00"
    out = ovpn_parse.classify_response(response)
    assert out["is_openvpn"] is True
    assert out["opcode"] == 8
    assert out["key_id"] == 0


def test_classify_response_rejects_other_opcode():
    # opcode 6 (P_DATA_V1) is not a handshake response.
    response = bytes([6 << 3]) + b"\x00" * 13
    out = ovpn_parse.classify_response(response)
    assert out["is_openvpn"] is False
    assert out["opcode"] == 6


def test_classify_response_nonzero_key_id_still_matches_opcode():
    # opcode 8, key_id 3 -> (8 << 3) | 3 = 0x43
    response = bytes([(8 << 3) | 3]) + b"\x00" * 13
    out = ovpn_parse.classify_response(response)
    assert out["is_openvpn"] is True
    assert out["key_id"] == 3


def test_classify_response_empty_is_no_response_not_error():
    out = ovpn_parse.classify_response(b"")
    assert out == {"is_openvpn": False, "note": "no response"}


def test_parse_openvpn_result_fingerprinted_includes_cve_caveat():
    raw = ovpn_parse.RawOpenvpnProbeResult(
        target="10.0.0.5", host="10.0.0.5", port=1194, protocol="udp",
        response_bytes=bytes([8 << 3]) + b"\x00" * 13,
    )
    out = ovpn_parse.parse_openvpn_result(raw)
    assert out["status"] == "fingerprinted"
    assert out["is_openvpn"] is True
    assert "CVE-2020-15078" in out["note"]


def test_parse_openvpn_result_no_match():
    raw = ovpn_parse.RawOpenvpnProbeResult(
        target="10.0.0.5", host="10.0.0.5", port=1194, protocol="udp", response_bytes=b""
    )
    out = ovpn_parse.parse_openvpn_result(raw)
    assert out["status"] == "no_match"
    assert out["is_openvpn"] is False


def test_parse_openvpn_result_error_passthrough():
    raw = ovpn_parse.RawOpenvpnProbeResult(target="bad", error="invalid target: 'bad'")
    out = ovpn_parse.parse_openvpn_result(raw)
    assert out["status"] == "failed"
    assert out["error"] == "invalid target: 'bad'"


# ---------------------------------------------------------------------------
# execute.py: UDP
# ---------------------------------------------------------------------------


def test_execute_udp_fingerprint_match():
    server_reply = bytes([8 << 3]) + b"\xbb" * 8 + b"\x00" + b"\x00\x00\x00\x00"
    mock_sock = MagicMock()
    mock_sock.recvfrom.return_value = (server_reply, ("10.0.0.5", 1194))

    with patch("socket.socket", return_value=mock_sock):
        raw = ovpn_execute(target="10.0.0.5", port=1194, protocol="udp", timeout=3)

    assert raw.error is None
    assert raw.response_bytes == server_reply
    mock_sock.settimeout.assert_called_once_with(3.0)
    sent_packet = mock_sock.sendto.call_args.args[0]
    assert len(sent_packet) == 14
    assert sent_packet[0] == (7 << 3)


def test_execute_udp_timeout_is_clean_empty_response_not_error():
    mock_sock = MagicMock()
    mock_sock.recvfrom.side_effect = socket.timeout()

    with patch("socket.socket", return_value=mock_sock):
        raw = ovpn_execute(target="10.0.0.5", port=1194, protocol="udp", timeout=2)

    assert raw.error is None
    assert raw.response_bytes == b""
    parsed = ovpn_parse.parse_openvpn_result(raw)
    assert parsed["status"] == "no_match"


# ---------------------------------------------------------------------------
# execute.py: TCP
# ---------------------------------------------------------------------------


def test_execute_tcp_fingerprint_match_strips_length_prefix():
    server_reply = bytes([8 << 3]) + b"\xcc" * 8 + b"\x00" + b"\x00\x00\x00\x00"
    framed = len(server_reply).to_bytes(2, "big") + server_reply
    mock_sock = MagicMock()
    # First recv(2) returns the length prefix, second recv(len) returns the payload.
    mock_sock.recv.side_effect = [framed[:2], framed[2:]]

    with patch("socket.socket", return_value=mock_sock):
        raw = ovpn_execute(target="10.0.0.5", port=1194, protocol="tcp", timeout=3)

    assert raw.error is None
    assert raw.response_bytes == server_reply
    mock_sock.connect.assert_called_once_with(("10.0.0.5", 1194))
    sent = mock_sock.sendall.call_args.args[0]
    assert sent[:2] == (14).to_bytes(2, "big")
    assert len(sent) == 16


def test_execute_tcp_connect_timeout_is_clean_empty_response():
    mock_sock = MagicMock()
    mock_sock.connect.side_effect = socket.timeout()

    with patch("socket.socket", return_value=mock_sock):
        raw = ovpn_execute(target="10.0.0.5", port=1194, protocol="tcp", timeout=2)

    assert raw.error is None
    assert raw.response_bytes == b""


def test_execute_tcp_connection_refused_is_an_error():
    mock_sock = MagicMock()
    mock_sock.connect.side_effect = ConnectionRefusedError()

    with patch("socket.socket", return_value=mock_sock):
        raw = ovpn_execute(target="10.0.0.5", port=1194, protocol="tcp", timeout=2)

    assert raw.error == "connection refused (TCP port closed)"


# ---------------------------------------------------------------------------
# execute.py: validation
# ---------------------------------------------------------------------------


def test_execute_rejects_invalid_target():
    raw = ovpn_execute(target="   ", port=1194)
    assert "invalid target" in raw.error


def test_execute_rejects_invalid_port():
    raw = ovpn_execute(target="10.0.0.5", port=99999)
    assert "invalid port" in raw.error


def test_execute_rejects_invalid_protocol():
    raw = ovpn_execute(target="10.0.0.5", protocol="icmp")
    assert "protocol must be one of" in raw.error


def test_execute_dns_failure_is_an_error():
    mock_sock = MagicMock()
    mock_sock.sendto.side_effect = socket.gaierror("Name or service not known")

    with patch("socket.socket", return_value=mock_sock):
        raw = ovpn_execute(target="nonexistent.invalid", port=1194, protocol="udp")

    assert "DNS resolution failed" in raw.error


# ---------------------------------------------------------------------------
# Tool glue
# ---------------------------------------------------------------------------


def test_tool_identity_and_contract():
    tool = OpenvpnProbe()
    assert tool.tool_id == "openvpn_probe"
    assert tool.spec.name == "openvpn_probe"
    assert tool.scope_param == "target"
    assert tool.destructive is False
    assert tool.required_binary is None
    assert any(t.tool_id == "openvpn_probe" for t in ALL_TOOLS)


def test_tool_run_end_to_end():
    server_reply = bytes([8 << 3]) + b"\x00" * 13
    mock_sock = MagicMock()
    mock_sock.recvfrom.return_value = (server_reply, ("10.0.0.5", 1194))

    with patch("socket.socket", return_value=mock_sock):
        tool = OpenvpnProbe()
        result = tool.run(target="10.0.0.5")

    assert result["status"] == "fingerprinted"
    assert result["is_openvpn"] is True


def test_profile_membership():
    web = load_profile("web")
    cloud = load_profile("cloud")
    ad_network = load_profile("ad-network")
    kubernetes = load_profile("kubernetes")
    assert "openvpn_probe" in web
    assert "openvpn_probe" in cloud
    assert "openvpn_probe" in ad_network
    assert "openvpn_probe" not in kubernetes
