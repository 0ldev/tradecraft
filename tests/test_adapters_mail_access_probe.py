from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from tradecraft.adapters.mail_access_probe.execute import (
    RawMailAccessResult,
    detect_protocol,
    execute,
    is_implicit_tls,
    normalize_host,
    probe_imap,
    probe_pop3,
)
from tradecraft.adapters.mail_access_probe.parse import (
    evaluate_cleartext_auth,
    extract_auth_mechanisms,
    infer_software,
    parse_result,
)


class TestTargetResolution:
    def test_normalize_host(self):
        assert normalize_host("http://mail.example.com") == "mail.example.com"
        assert normalize_host("mail.example.com/imap") == "mail.example.com"
        assert normalize_host("mail.example.com:143") == "mail.example.com"
        assert normalize_host("[2001:db8::1]:993") == "2001:db8::1"
        assert normalize_host("192.168.1.10") == "192.168.1.10"

    def test_detect_protocol(self):
        assert detect_protocol(143) == "imap"
        assert detect_protocol(993) == "imap"
        assert detect_protocol(110) == "pop3"
        assert detect_protocol(995) == "pop3"
        assert detect_protocol(8143, "imap") == "imap"
        assert detect_protocol(8110, "pop3") == "pop3"

    def test_is_implicit_tls(self):
        assert is_implicit_tls(993) is True
        assert is_implicit_tls(995) is True
        assert is_implicit_tls(143) is False
        assert is_implicit_tls(110) is False


class TestBannerAndCapabilitiesParsing:
    def test_infer_software(self):
        assert infer_software("* OK Dovecot ready.") == "Dovecot"
        assert infer_software("* OK Dovecot 2.3.16 ready.") == "Dovecot 2.3.16"
        assert infer_software("* OK Courier-IMAP 4.0.6 ready.") == "Courier 4.0.6"
        assert infer_software("* OK The Microsoft Exchange IMAP4 service is ready.") == "Microsoft Exchange"
        assert infer_software("* OK Zimbra 8.8.15 ready.") == "Zimbra"
        assert infer_software("+OK Cyrus POP3 v2.4.17 ready") == "Cyrus 2.4.17"
        assert infer_software("* OK Generic Server ready.") is None

    def test_extract_auth_mechanisms_imap(self):
        caps = ["IMAP4rev1", "STARTTLS", "AUTH=PLAIN", "AUTH=LOGIN", "AUTH=CRAM-MD5", "LOGINDISABLED"]
        mechs = extract_auth_mechanisms("imap", caps)
        assert mechs == ["PLAIN", "LOGIN", "CRAM-MD5"]

    def test_extract_auth_mechanisms_pop3(self):
        caps = ["USER", "RESP-CODES", "STLS", "SASL PLAIN LOGIN DIGEST-MD5"]
        mechs = extract_auth_mechanisms("pop3", caps)
        assert mechs == ["PLAIN", "LOGIN", "DIGEST-MD5"]


class TestCleartextAuthAudit:
    def test_imap_plaintext_without_logindisabled_is_vulnerable(self):
        caps = ["IMAP4rev1", "STARTTLS", "AUTH=PLAIN"]
        vuln, reason = evaluate_cleartext_auth("imap", is_tls=False, capabilities=caps)
        assert vuln is True
        assert "RFC 3501" in reason

    def test_imap_plaintext_with_logindisabled_and_no_plain_auth_is_secure(self):
        caps = ["IMAP4rev1", "STARTTLS", "LOGINDISABLED"]
        vuln, reason = evaluate_cleartext_auth("imap", is_tls=False, capabilities=caps)
        assert vuln is False
        assert reason is None

    def test_imap_with_tls_is_secure(self):
        caps = ["IMAP4rev1", "AUTH=PLAIN"]
        vuln, reason = evaluate_cleartext_auth("imap", is_tls=True, capabilities=caps)
        assert vuln is False
        assert reason is None

    def test_pop3_plaintext_with_user_is_vulnerable(self):
        caps = ["USER", "RESP-CODES", "STLS"]
        vuln, reason = evaluate_cleartext_auth("pop3", is_tls=False, capabilities=caps)
        assert vuln is True
        assert "RFC 1939" in reason

    def test_pop3_with_tls_is_secure(self):
        caps = ["USER", "SASL PLAIN"]
        vuln, reason = evaluate_cleartext_auth("pop3", is_tls=True, capabilities=caps)
        assert vuln is False
        assert reason is None


class TestParseResult:
    def test_parse_connected_vulnerable_imap(self):
        raw = RawMailAccessResult(
            target="mail.example.com",
            host="mail.example.com",
            port=143,
            protocol="imap",
            connected=True,
            banner="* OK Dovecot 2.3 ready.",
            is_tls=False,
            starttls_advertised=True,
            capabilities_pre_tls=["IMAP4rev1", "STARTTLS", "AUTH=PLAIN"],
            rtt_ms=15.2,
        )
        parsed = parse_result(raw)
        assert parsed["connected"] is True
        assert parsed["software"] == "Dovecot 2.3"
        assert parsed["security_audit"]["cleartext_auth_allowed"] is True
        assert parsed["security_audit"]["severity"] == "medium"
        assert parsed["tls"]["mode"] == "plaintext"
        assert "PLAIN" in parsed["auth_mechanisms"]

    def test_parse_connected_secure_imaps(self):
        raw = RawMailAccessResult(
            target="mail.example.com",
            host="mail.example.com",
            port=993,
            protocol="imap",
            connected=True,
            banner="* OK Dovecot ready.",
            is_tls=True,
            implicit_tls=True,
            tls_cipher="TLS_AES_256_GCM_SHA384",
            tls_version="TLSv1.3",
            capabilities_pre_tls=["IMAP4rev1", "AUTH=PLAIN"],
            rtt_ms=12.5,
        )
        parsed = parse_result(raw)
        assert parsed["connected"] is True
        assert parsed["tls"]["mode"] == "implicit_tls"
        assert parsed["security_audit"]["cleartext_auth_allowed"] is False
        assert parsed["security_audit"]["vulnerability"] is None

    def test_parse_error(self):
        raw = RawMailAccessResult(
            target="mail.example.com",
            host="mail.example.com",
            port=143,
            connected=False,
            error="Connection refused on mail.example.com:143",
        )
        parsed = parse_result(raw)
        assert parsed["connected"] is False
        assert "Connection refused" in parsed["error"]


class TestMockedExecution:
    @patch("tradecraft.adapters.mail_access_probe.execute.socket.socket")
    def test_execute_imap_mock(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        # Mock conversation:
        # 1. Greeting
        # 2. A001 CAPABILITY response
        # 3. A002 STARTTLS (rejected or disabled for test)
        # 4. A999 LOGOUT
        responses = [
            b"* OK Dovecot 2.3 ready.\r\n",
            b"* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN LOGINDISABLED\r\nA001 OK CAPABILITY completed.\r\n",
        ]
        mock_sock.recv.side_effect = responses + [b""]

        raw = execute("mail.example.com", port=143, starttls=False)
        assert raw.connected is True
        assert raw.protocol == "imap"
        assert "Dovecot 2.3" in raw.banner
        assert "IMAP4rev1" in raw.capabilities_pre_tls
        assert raw.starttls_advertised is True

    @patch("tradecraft.adapters.mail_access_probe.execute.socket.socket")
    def test_execute_pop3_mock(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        responses = [
            b"+OK Dovecot ready.\r\n",
            b"+OK Capability list follows\r\nUSER\r\nSTLS\r\nSASL PLAIN\r\n.\r\n",
        ]
        mock_sock.recv.side_effect = responses + [b""]

        raw = execute("mail.example.com", port=110, starttls=False)
        assert raw.connected is True
        assert raw.protocol == "pop3"
        assert "+OK Dovecot" in raw.banner
        assert "USER" in raw.capabilities_pre_tls
        assert raw.starttls_advertised is True
