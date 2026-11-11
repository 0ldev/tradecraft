"""
Unit tests for SMTP probe adapter (execution and parsing).
"""
import socket
from unittest.mock import MagicMock, patch

from tradecraft.adapters.smtp_probe.execute import (
    SmtpResult,
    execute,
    infer_software,
    normalize_host,
    read_smtp_response,
)
from tradecraft.adapters.smtp_probe.parse import parse


def test_normalize_host():
    assert normalize_host("mail.example.com") == "mail.example.com"
    assert normalize_host("smtp://mail.example.com:25") == "mail.example.com"
    assert normalize_host("192.168.1.10:587") == "192.168.1.10"
    assert normalize_host("  mail.target.br/  ") == "mail.target.br"


def test_infer_software():
    assert infer_software("220 mail.domain.com ESMTP Exim 4.96") == "Exim 4.96"
    assert infer_software("220 mail.domain.com ESMTP Postfix (Ubuntu)") == "Postfix (Ubuntu)"
    assert infer_software("220 Microsoft ESMTP MAIL Service ready") == "Microsoft Exchange"
    assert infer_software("220 Dovecot ready") == "Dovecot"
    assert infer_software("220 Generic SMTP Server") is None


def test_read_smtp_response_multiline():
    mock_sock = MagicMock()
    mock_sock.recv.side_effect = [
        b"250-mail.example.com Hello\r\n250-SIZE 52428800\r\n250-STARTTLS\r\n250 HELP\r\n"
    ]
    code, lines = read_smtp_response(mock_sock)
    assert code == 250
    assert len(lines) == 4
    assert lines[0] == "250-mail.example.com Hello"
    assert lines[3] == "250 HELP"


@patch("socket.socket")
def test_execute_vrfy_oracle_detected(mock_sock_cls):
    mock_sock = MagicMock()
    mock_sock_cls.return_value = mock_sock

    mock_sock.recv.side_effect = [
        b"220 mail.example.com ESMTP Postfix\r\n",  # Banner
        b"250-mail.example.com\r\n250-STARTTLS\r\n250 HELP\r\n",  # EHLO
        b"250 2.1.5 root <root@example.com>\r\n",  # VRFY positive response
        b"221 Bye\r\n",  # QUIT
    ]

    res = execute("mail.example.com", port=25, starttls=False, vrfy_target="root", timeout=3)
    assert res.connected is True
    assert res.software == "Postfix"
    assert res.vrfy_tested is True
    assert res.vrfy_code == 250
    assert res.user_enumeration_oracle is True


@patch("socket.socket")
def test_execute_real_captured_exim_with_admin_prohibition(mock_sock_cls):
    mock_sock = MagicMock()
    mock_sock_cls.return_value = mock_sock

    # Real captured conversation from examplepaint.com.br:587
    banner = b"220-smtp01.examplepaint.com.br ESMTP Exim 4.92 #2\r\n220 Bulk mail prohibited\r\n"
    ehlo = b"250-smtp01.examplepaint.com.br Hello\r\n250-SIZE 52428800\r\n250-STARTTLS\r\n250 HELP\r\n"
    vrfy = b"252 Administrative prohibition\r\n"

    mock_sock.recv.side_effect = [banner, ehlo, vrfy, b"221 Bye\r\n"]

    res = execute("examplepaint.com.br", port=587, starttls=False, vrfy_target="root@examplepaint.com.br", timeout=3)
    assert res.connected is True
    assert res.software == "Exim 4.92"
    assert res.starttls_advertised is True
    assert res.vrfy_code == 252
    assert res.user_enumeration_oracle is False  # 252 does not confirm user existence


def test_parse_structure_and_findings():
    res = SmtpResult(
        target="mail.example.com",
        host="mail.example.com",
        port=25,
        connected=True,
        banner="220 mail.example.com ESMTP",
        software="Exim 4.96",
        extensions=["STARTTLS", "AUTH PLAIN LOGIN"],
        starttls_advertised=True,
        starttls_active=False,
        auth_mechanisms=["PLAIN", "LOGIN"],
        vrfy_tested=True,
        vrfy_target="admin@example.com",
        vrfy_code=250,
        vrfy_response="250 admin@example.com",
        user_enumeration_oracle=True,
        rtt_ms=45.0,
    )
    parsed = parse(res)
    assert parsed["software"] == "Exim 4.96"
    assert parsed["vrfy"]["user_enumeration_oracle"] is True
    assert len(parsed["findings"]) == 2  # VRFY oracle + Insecure Plaintext Auth
    assert "VRFY User Enumeration Oracle" in parsed["findings"][0]
    assert "Insecure SMTP Authentication" in parsed["findings"][1]
