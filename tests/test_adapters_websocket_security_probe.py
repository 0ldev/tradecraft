"""Unit tests for websocket_security_probe adapter (raw socket, no real network)."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from tradecraft.adapters.websocket_security_probe.execute import _parse_host_port, execute
from tradecraft.adapters.websocket_security_probe.parse import parse

ACCEPT_RESPONSE = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
REJECT_RESPONSE = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"


def _sock_with_response(response: bytes):
    sock = MagicMock()
    sock.recv.side_effect = [response, b""]
    return sock


def test_parse_host_port_bare_host_port():
    assert _parse_host_port("chat.example.com:443", default_port=80) == ("chat.example.com", 443)


def test_parse_host_port_url():
    assert _parse_host_port("wss://chat.example.com/socket", default_port=80) == ("chat.example.com", 80)


def test_parse_host_port_bare_host_no_port():
    assert _parse_host_port("chat.example.com", default_port=443) == ("chat.example.com", 443)


@patch("socket.socket")
def test_execute_default_origins_same_origin_and_cross_origin(mock_sock_cls):
    mock_sock_cls.side_effect = [
        _sock_with_response(ACCEPT_RESPONSE),
        _sock_with_response(REJECT_RESPONSE),
    ]
    run = execute(target="chat.example.com:80")
    assert run.error is None
    labels = [a.origin_label for a in run.attempts]
    assert labels == ["same-origin", "https://evil.tradecraft-probe.test"]
    assert run.attempts[0].accepted is True
    assert run.attempts[1].accepted is False


@patch("socket.socket")
def test_execute_sends_origin_header_in_handshake(mock_sock_cls):
    sock = _sock_with_response(ACCEPT_RESPONSE)
    mock_sock_cls.side_effect = [sock, _sock_with_response(REJECT_RESPONSE)]
    execute(target="chat.example.com:80")
    sent = sock.sendall.call_args[0][0]
    assert b"Origin: http://chat.example.com" in sent
    assert b"Upgrade: websocket" in sent


def test_parse_flags_cross_origin_accepted_as_vulnerable():
    with patch("socket.socket") as mock_sock_cls:
        mock_sock_cls.side_effect = [
            _sock_with_response(ACCEPT_RESPONSE),
            _sock_with_response(ACCEPT_RESPONSE),
        ]
        run = execute(target="chat.example.com:80")
    result = parse(run)
    assert result["vulnerable"] is True
    assert "https://evil.tradecraft-probe.test" in result["cross_origin_accepted"]


def test_parse_clean_when_cross_origin_rejected():
    with patch("socket.socket") as mock_sock_cls:
        mock_sock_cls.side_effect = [
            _sock_with_response(ACCEPT_RESPONSE),
            _sock_with_response(REJECT_RESPONSE),
        ]
        run = execute(target="chat.example.com:80")
    result = parse(run)
    assert result["vulnerable"] is False


def test_execute_invalid_target_errors():
    run = execute(target="")
    result = parse(run)
    assert "error" in result
