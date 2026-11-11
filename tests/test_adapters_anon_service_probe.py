"""
Unit tests for anon_service_probe adapter (execution and parsing).
"""
import socket
import struct
from unittest.mock import MagicMock, patch

from tradecraft.adapters.anon_service_probe.execute import (
    AnonServiceResult,
    FtpResult,
    MySqlResult,
    execute,
    normalize_host,
    probe_ftp,
    probe_mysql,
)
from tradecraft.adapters.anon_service_probe.parse import parse


def test_normalize_host():
    assert normalize_host("203.0.113.41") == "203.0.113.41"
    assert normalize_host("ftp://files.example.com:21/pub") == "files.example.com"
    assert normalize_host("mysql.internal:3306") == "mysql.internal"
    assert normalize_host("  target.host/  ") == "target.host"


@patch("socket.socket")
def test_probe_ftp_vulnerable_anonymous(mock_sock_cls):
    mock_sock = MagicMock()
    mock_sock_cls.return_value = mock_sock
    mock_sock.recv.side_effect = [
        b"220 FTP Server ready.\r\n",
        b"331 Password required for anonymous\r\n",
        b"230 User logged in, proceed.\r\n",
    ]

    res = probe_ftp("example.com", 21, timeout=3.0)
    assert res.connected is True
    assert res.anonymous_login is True
    assert res.vulnerable is True
    assert res.status == "vulnerable"
    assert "User logged in" in res.server_response


@patch("socket.socket")
def test_probe_ftp_access_denied(mock_sock_cls):
    mock_sock = MagicMock()
    mock_sock_cls.return_value = mock_sock
    mock_sock.recv.side_effect = [
        b"220 FTP Server ready.\r\n",
        b"331 Password required for anonymous\r\n",
        b"530 Login incorrect.\r\n",
    ]

    res = probe_ftp("example.com", 21, timeout=3.0)
    assert res.connected is True
    assert res.anonymous_login is False
    assert res.vulnerable is False
    assert res.status == "access_denied"


@patch("socket.socket")
def test_probe_mysql_empty_root_vulnerable(mock_sock_cls):
    mock_sock = MagicMock()
    mock_sock_cls.return_value = mock_sock

    # Handshake body: proto=10, ver="8.0.32\x00", conn_id=123, rest...
    handshake_body = b"\x0a8.0.32\x00\x01\x00\x00\x00auth_plugin_data\x00\x00\x00mysql_native_password\x00"
    handshake_hdr = struct.pack("<I", len(handshake_body))[:3] + b"\x00"

    # OK packet response: 0x00
    ok_body = b"\x00\x00\x00\x02\x00\x00\x00"
    ok_hdr = struct.pack("<I", len(ok_body))[:3] + b"\x02"

    mock_sock.recv.side_effect = [
        handshake_hdr,
        handshake_body,
        ok_hdr,
        ok_body,
    ]

    res = probe_mysql("db.example.com", 3306, timeout=3.0)
    assert res.connected is True
    assert res.server_version == "8.0.32"
    assert res.empty_root_password is True
    assert res.vulnerable is True
    assert res.status == "vulnerable"


@patch("socket.socket")
def test_probe_mysql_access_denied_real_mariadb_output(mock_sock_cls):
    mock_sock = MagicMock()
    mock_sock_cls.return_value = mock_sock

    # Real MariaDB handshake captured from a live probe, not hand-typed
    handshake_body = b"\x0a11.8.9-MariaDB-log\x00\\^\x83\x04o2IVT%Xk\x00\xfe\xff\xe0\x02\x00\xff\x81\x15\x00\x00\x00\x00\x00\x00=\x00\x00\x005dxN\\eeN4W;b\x00mysql_native_password\x00"
    handshake_hdr = struct.pack("<I", len(handshake_body))[:3] + b"\x00"

    # Real Error 1045 access denied response
    # 0xff, errno=1045 (0x15, 0x04), sqlstate="#28000", msg="Access denied for user 'root'@'...' (using password: NO)"
    msg = b"Access denied for user 'root'@'203.0.113.10' (using password: NO)"
    err_body = b"\xff\x15\x04#28000" + msg
    err_hdr = struct.pack("<I", len(err_body))[:3] + b"\x02"

    mock_sock.recv.side_effect = [
        handshake_hdr,
        handshake_body,
        err_hdr,
        err_body,
    ]

    res = probe_mysql("203.0.113.41", 3306, timeout=3.0)
    assert res.connected is True
    assert res.server_version == "11.8.9-MariaDB-log"
    assert res.empty_root_password is False
    assert res.vulnerable is False
    assert res.error_code == 1045
    assert "Access denied" in res.server_message


def test_parse_vulnerable_and_denied():
    ftp_res = FtpResult(
        host="203.0.113.41",
        port=21,
        connected=True,
        banner="220 FTP Server ready.",
        anonymous_login=True,
        vulnerable=True,
        status="vulnerable",
        server_response="230 Login successful",
    )
    mysql_res = MySqlResult(
        host="203.0.113.41",
        port=3306,
        connected=True,
        server_version="11.8.9-MariaDB-log",
        empty_root_password=False,
        vulnerable=False,
        status="access_denied",
        error_code=1045,
        server_message="Access denied",
    )
    combined = AnonServiceResult(
        target="203.0.113.41",
        host="203.0.113.41",
        ftp=ftp_res,
        mysql=mysql_res,
        vulnerable=True,
        summary="FTP VULNERABLE",
    )

    parsed = parse(combined)
    assert parsed["vulnerable"] is True
    assert len(parsed["findings"]) == 1
    assert "FTP Anonymous Login" in parsed["findings"][0]
    assert parsed["mysql"]["status"] == "access_denied"
