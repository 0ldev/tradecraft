"""Unit tests for the ntlm_info_disclosure_probe adapter. Builds real
NTLMSSP Type-2 messages and mocks requests.get."""
from __future__ import annotations

import base64
import struct
from unittest.mock import MagicMock, patch

import pytest

from tradecraft.adapters.ntlm_info_disclosure_probe.execute import (
    NTLM_SIGNATURE,
    build_type1_message,
    execute,
    parse_type2_message,
    type1_header_value,
)
from tradecraft.adapters.ntlm_info_disclosure_probe.parse import parse


def _av_pair(av_id, value):
    encoded = value.encode("utf-16-le")
    return struct.pack("<HH", av_id, len(encoded)) + encoded


def _type2_message(target_name="EXAMPLE", av_pairs=None):
    if av_pairs is None:
        av_pairs = (
            _av_pair(1, "DC01")
            + _av_pair(2, "EXAMPLE")
            + _av_pair(3, "dc01.example.com")
            + _av_pair(4, "example.com")
            + struct.pack("<HH", 0, 0)
        )
    target = target_name.encode("utf-16-le")
    target_offset = 48
    info_offset = target_offset + len(target)
    header = (
        struct.pack("<8sI", NTLM_SIGNATURE, 2)
        + struct.pack("<HHI", len(target), len(target), target_offset)
        + struct.pack("<I", 0x00000001)  # NEGOTIATE_UNICODE
        + b"\x11" * 8  # server challenge
        + b"\x00" * 8  # reserved
        + struct.pack("<HHI", len(av_pairs), len(av_pairs), info_offset)
    )
    return header + target + av_pairs


def _mock_response(status_code, authenticate_values):
    resp = MagicMock()
    resp.status_code = status_code
    resp.raw.headers.getlist.return_value = authenticate_values
    resp.headers = {}
    return resp


def test_build_type1_message_has_signature_and_type():
    message = build_type1_message()
    assert message[:8] == NTLM_SIGNATURE
    assert struct.unpack_from("<I", message, 8)[0] == 1
    assert len(message) == 32
    assert type1_header_value().startswith("NTLM ")


def test_parse_type2_discloses_target_names_and_av_pairs():
    parsed = parse_type2_message(_type2_message())
    assert parsed["target_name"] == "EXAMPLE"
    assert parsed["nb_computer_name"] == "DC01"
    assert parsed["nb_domain_name"] == "EXAMPLE"
    assert parsed["dns_computer_name"] == "dc01.example.com"
    assert parsed["dns_domain_name"] == "example.com"
    assert parsed["server_challenge"] == "11" * 8


def test_parse_type2_rejects_non_ntlm_and_wrong_type():
    with pytest.raises(ValueError, match="signature"):
        parse_type2_message(b"NOTNTLM\x00" + b"\x00" * 64)
    with pytest.raises(ValueError, match="Type-2"):
        bad = bytearray(_type2_message())
        struct.pack_into("<I", bad, 8, 1)
        parse_type2_message(bytes(bad))


def test_execute_extracts_ntlm_challenge():
    token = base64.b64encode(_type2_message()).decode("ascii")
    with patch("tradecraft.adapters.ntlm_info_disclosure_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.get.return_value = _mock_response(401, [f"NTLM {token}"])
        raw = execute(target="https://owa.example.com/owa/")

    result = parse(raw)
    assert result["ntlm_supported"] is True
    assert result["challenge_received"] is True
    assert result["disclosed"] is True
    assert result["domain"] == "EXAMPLE"
    assert result["computer_name"] == "DC01"
    assert "EXAMPLE" in result["summary"]


def test_execute_accepts_negotiate_wrapped_ntlm():
    token = base64.b64encode(_type2_message()).decode("ascii")
    with patch("tradecraft.adapters.ntlm_info_disclosure_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.get.return_value = _mock_response(401, [f"Negotiate {token}"])
        raw = execute(target="https://vpn.example.com/")

    result = parse(raw)
    assert raw.auth_scheme == "Negotiate"
    assert result["disclosed"] is True


def test_execute_reports_missing_ntlm_challenge():
    with patch("tradecraft.adapters.ntlm_info_disclosure_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.get.return_value = _mock_response(401, ["Basic realm=example"])
        raw = execute(target="https://example.com/")

    result = parse(raw)
    assert result["ntlm_supported"] is False
    assert result["disclosed"] is False
    assert "no NTLM Type-2 challenge" in result["error"]


def test_execute_rejects_malformed_challenge_token():
    with patch("tradecraft.adapters.ntlm_info_disclosure_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.get.return_value = _mock_response(401, ["NTLM not-base64!!"])
        raw = execute(target="https://example.com/")

    result = parse(raw)
    assert result["disclosed"] is False
    assert "invalid NTLM Type-2 challenge" in result["error"]


def test_execute_network_error_is_reported():
    with patch("tradecraft.adapters.ntlm_info_disclosure_probe.execute.requests") as mock_requests:
        mock_requests.RequestException = Exception
        mock_requests.get.side_effect = Exception("timeout")
        raw = execute(target="https://example.com/")

    result = parse(raw)
    assert result["disclosed"] is False
    assert "timeout" in result["error"]
