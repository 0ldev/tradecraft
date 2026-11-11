"""
Tests for TCP probe adapter (execution and parsing).
"""
import socket
import ssl
from unittest.mock import MagicMock, patch

from tradecraft.adapters.tcp_probe.execute import ProbeResult, execute, normalize_host
from tradecraft.adapters.tcp_probe.parse import identify_service, parse, sanitize_printable


def test_normalize_host():
    assert normalize_host("example.com") == "example.com"
    assert normalize_host("http://example.com/some/path") == "example.com"
    assert normalize_host("https://api.example.com:8443/test") == "api.example.com"
    assert normalize_host("192.168.1.1:1001") == "192.168.1.1"
    assert normalize_host("[2001:db8::1]:80") == "2001:db8::1"
    assert normalize_host("  target.local/  ") == "target.local"


def test_identify_service():
    assert identify_service("SSH-2.0-OpenSSH_8.9p1", b"SSH-2.0-OpenSSH_8.9p1\r\n", 22) == "ssh"
    assert identify_service("HTTP/1.1 200 OK\r\nServer: nginx", b"HTTP/1.1 200 OK", 80) == "http"
    assert identify_service("220 mail.example.com ESMTP Exim 4.96", b"220 mail...", 25) == "smtp"
    assert identify_service("220 (vsFTPd 3.0.3)", b"220 (vsFTPd 3.0.3)", 21) == "ftp"
    assert identify_service("5.7.38-0ubuntu0.18.04.1", b"\x4a\x00\x00\x00\x0a\x35\x2e\x37mysql_native_password", 3306) == "mysql"
    assert identify_service("+PONG", b"+PONG\r\n", 6379) == "redis"
    assert identify_service("", b"RFB 003.008\n", 5900) == "vnc"
    assert identify_service("+OK Dovecot ready.", b"+OK Dovecot", 110) == "pop3"
    assert identify_service("* OK IMAP4rev1 server ready", b"* OK IMAP4rev1", 143) == "imap"
    assert identify_service("random noise", b"random noise", 9999) is None


def test_sanitize_printable():
    raw = "hello\x00\x00world\x01\nline2"
    sanitized = sanitize_printable(raw)
    assert "hello..world" in sanitized
    assert "\nline2" in sanitized


@patch("socket.socket")
def test_execute_success_banner_grab(mock_sock_cls):
    mock_sock = MagicMock()
    mock_sock_cls.return_value = mock_sock
    mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1\r\n"

    res = execute(target="192.168.1.50", port=22, timeout=3)
    assert res.connected is True
    assert res.status == "open"
    assert "SSH-2.0-OpenSSH" in res.banner_text
    mock_sock.connect.assert_called_with(("192.168.1.50", 22))


@patch("socket.socket")
def test_execute_tcpwrapped_zero_bytes_immediate_close(mock_sock_cls):
    mock_sock = MagicMock()
    mock_sock_cls.return_value = mock_sock
    mock_sock.recv.return_value = b""  # Peer closed connection immediately

    res = execute(target="examplepaint.com.br", port=1001, timeout=5)
    assert res.connected is True
    assert res.status == "closed_by_peer"
    assert "tcpwrapped" in res.note
    assert res.banner_text == ""


@patch("socket.socket")
def test_execute_connection_reset_by_peer(mock_sock_cls):
    mock_sock = MagicMock()
    mock_sock_cls.return_value = mock_sock
    mock_sock.sendall.side_effect = ConnectionResetError(104, "Connection reset by peer")

    res = execute(target="examplepaint.com.br", port=1001, send_data="HEAD / HTTP/1.0\r\n\r\n")
    assert res.status == "reset"
    assert "reset by peer" in res.error.lower()


@patch("socket.socket")
def test_execute_connection_refused(mock_sock_cls):
    mock_sock = MagicMock()
    mock_sock_cls.return_value = mock_sock
    mock_sock.connect.side_effect = ConnectionRefusedError(111, "Connection refused")

    res = execute(target="192.168.1.50", port=8080)
    assert res.connected is False
    assert res.status == "refused"


@patch("socket.socket")
def test_execute_timeout(mock_sock_cls):
    mock_sock = MagicMock()
    mock_sock_cls.return_value = mock_sock
    mock_sock.connect.side_effect = socket.timeout()

    res = execute(target="192.168.1.50", port=25, timeout=2)
    assert res.connected is False
    assert res.status == "timeout"


@patch("ssl.create_default_context")
@patch("socket.socket")
def test_execute_ssl_handshake(mock_sock_cls, mock_ssl_ctx_cls):
    mock_sock = MagicMock()
    mock_sock_cls.return_value = mock_sock
    mock_sslsock = MagicMock()
    mock_ctx = MagicMock()
    mock_ssl_ctx_cls.return_value = mock_ctx
    mock_ctx.wrap_socket.return_value = mock_sslsock
    mock_sslsock.recv.return_value = b"HTTP/1.1 200 OK\r\nServer: Apache\r\n"

    res = execute(target="examplepaint.com.br", port=443, ssl_probe=True, send_data="HEAD / HTTP/1.0\r\n\r\n")
    assert res.connected is True
    assert res.ssl_used is True
    assert res.status == "open"
    assert "Apache" in res.banner_text


def test_parse_structure():
    result = ProbeResult(
        target="example.com",
        host="example.com",
        port=22,
        connected=True,
        ssl_used=False,
        status="open",
        banner_bytes=b"SSH-2.0-OpenSSH_8.2\r\n",
        banner_text="SSH-2.0-OpenSSH_8.2",
        rtt_ms=12.5,
    )
    parsed = parse(result)
    assert parsed["service"] == "ssh"
    assert parsed["status"] == "open"
    assert parsed["port"] == 22
    assert parsed["connected"] is True


def test_parse_real_captured_tcpwrapped_and_http():
    # Real captured tcpwrapped from examplepaint.com.br:1001
    res_1001 = ProbeResult(
        target="examplepaint.com.br",
        host="examplepaint.com.br",
        port=1001,
        connected=True,
        ssl_used=False,
        status="closed_by_peer",
        banner_bytes=b"",
        banner_hex="",
        banner_text="",
        rtt_ms=17.53,
        note="TCP handshake succeeded, but remote peer closed connection immediately with 0 bytes (typical tcpwrapped or firewalled port).",
    )
    p_1001 = parse(res_1001)
    assert p_1001["status"] == "closed_by_peer"
    assert p_1001["service"] is None
    assert "tcpwrapped" in p_1001["note"]

    # Real captured Apache banner from examplepaint.com.br:80
    res_80 = ProbeResult(
        target="examplepaint.com.br",
        host="examplepaint.com.br",
        port=80,
        connected=True,
        ssl_used=False,
        status="open",
        banner_bytes=b"HTTP/1.1 200 OK\r\nServer: Apache\r\n",
        banner_hex="485454502f312e31",
        banner_text="HTTP/1.1 200 OK\r\nServer: Apache\r\n",
        rtt_ms=32.45,
    )
    p_80 = parse(res_80)
    assert p_80["status"] == "open"
    assert p_80["service"] == "http"
    assert "Apache" in p_80["banner"]

