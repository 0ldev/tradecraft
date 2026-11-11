"""
Execution logic for anonymous service authentication probing (FTP & MySQL).
Performs single-attempt, non-destructive checks for unauthenticated access.
"""
from __future__ import annotations

import socket
import struct
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import List, Optional


def normalize_host(target: str) -> str:
    """Extracts a clean hostname or IP address from target."""
    raw = target.strip()
    if "://" in raw:
        parsed = urllib.parse.urlsplit(raw)
        host = parsed.hostname or raw
        return host.strip()
    if "/" in raw:
        raw = raw.split("/", 1)[0]
    if ":" in raw:
        if raw.startswith("[") and "]" in raw:
            return raw[1 : raw.index("]")]
        parts = raw.split(":")
        if len(parts) == 2 and parts[1].isdigit():
            return parts[0].strip()
    return raw.strip()


@dataclass
class FtpResult:
    host: str
    port: int
    connected: bool = False
    banner: str = ""
    anonymous_login: bool = False
    vulnerable: bool = False
    status: str = "unknown"  # "vulnerable", "access_denied", "timeout", "refused", "error"
    server_response: str = ""
    files_sample: List[str] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class MySqlResult:
    host: str
    port: int
    connected: bool = False
    server_version: str = ""
    auth_plugin: str = ""
    empty_root_password: bool = False
    vulnerable: bool = False
    status: str = "unknown"  # "vulnerable", "access_denied", "timeout", "refused", "error"
    error_code: Optional[int] = None
    server_message: str = ""
    error: Optional[str] = None


@dataclass
class AnonServiceResult:
    target: str
    host: str
    ftp: Optional[FtpResult] = None
    mysql: Optional[MySqlResult] = None
    vulnerable: bool = False
    summary: str = ""
    error: Optional[str] = None


def probe_ftp(host: str, port: int = 21, timeout: float = 5.0) -> FtpResult:
    """Performs a single anonymous FTP login probe."""
    res = FtpResult(host=host, port=port)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)

    try:
        s.connect((host, port))
        res.connected = True

        banner_raw = s.recv(1024)
        res.banner = banner_raw.decode("latin-1", errors="replace").strip()

        # Send USER anonymous
        s.sendall(b"USER anonymous\r\n")
        resp_user = s.recv(1024).decode("latin-1", errors="replace").strip()

        if resp_user.startswith("230"):
            # Logged in without password
            res.anonymous_login = True
            res.vulnerable = True
            res.status = "vulnerable"
            res.server_response = resp_user
        elif resp_user.startswith("331"):
            # Password required
            s.sendall(b"PASS anonymous@tradecraft.local\r\n")
            resp_pass = s.recv(1024).decode("latin-1", errors="replace").strip()
            res.server_response = resp_pass
            if resp_pass.startswith("230"):
                res.anonymous_login = True
                res.vulnerable = True
                res.status = "vulnerable"
            else:
                res.anonymous_login = False
                res.vulnerable = False
                res.status = "access_denied"
        else:
            res.anonymous_login = False
            res.status = "access_denied"
            res.server_response = resp_user

        try:
            s.sendall(b"QUIT\r\n")
        except Exception:
            pass

    except ConnectionRefusedError:
        res.status = "refused"
        res.error = "Connection refused on FTP port"
    except (socket.timeout, TimeoutError):
        res.status = "timeout"
        res.error = f"FTP probe timed out after {timeout:.1f}s"
    except Exception as exc:
        res.status = "error"
        res.error = str(exc)
    finally:
        try:
            s.close()
        except Exception:
            pass

    return res


def probe_mysql(host: str, port: int = 3306, timeout: float = 5.0) -> MySqlResult:
    """Performs a single MySQL/MariaDB probe testing empty root password access."""
    res = MySqlResult(host=host, port=port)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)

    try:
        s.connect((host, port))
        res.connected = True

        hdr = s.recv(4)
        if len(hdr) < 4:
            res.status = "error"
            res.error = "Incomplete MySQL handshake header"
            return res

        plen = hdr[0] + (hdr[1] << 8) + (hdr[2] << 16)
        seq = hdr[3]
        body = s.recv(plen)
        if len(body) < 5:
            res.status = "error"
            res.error = "Incomplete MySQL handshake body"
            return res

        v_end = body.find(b"\x00", 1)
        if v_end != -1:
            res.server_version = body[1:v_end].decode("latin-1", errors="replace")

        if b"mysql_native_password" in body:
            res.auth_plugin = "mysql_native_password"
        elif b"caching_sha2_password" in body:
            res.auth_plugin = "caching_sha2_password"

        # Build Client Authentication Packet for user 'root' with empty password
        caps = 1 | 512 | 32768  # CLIENT_LONG_PASSWORD | CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION
        max_pkt = 16777216      # 16MB
        charset = 33            # utf8
        reserved = b"\x00" * 23
        user = b"root\x00"
        auth_resp = b"\x00"     # empty password length 0

        pkt_body = struct.pack("<IIB23s", caps, max_pkt, charset, reserved) + user + auth_resp
        pkt_hdr = struct.pack("<I", len(pkt_body))[:3] + bytes([seq + 1])
        s.sendall(pkt_hdr + pkt_body)

        resp_hdr = s.recv(4)
        if len(resp_hdr) >= 4:
            r_len = resp_hdr[0] + (resp_hdr[1] << 8) + (resp_hdr[2] << 16)
            r_body = s.recv(r_len)
            if r_body:
                if r_body[0] == 0x00:
                    res.empty_root_password = True
                    res.vulnerable = True
                    res.status = "vulnerable"
                    res.server_message = "Authentication successful (root user has no password)"
                elif r_body[0] == 0xFF:
                    res.empty_root_password = False
                    res.vulnerable = False
                    res.status = "access_denied"
                    if len(r_body) >= 3:
                        res.error_code = r_body[1] + (r_body[2] << 8)
                    # Message is after SQLSTATE marker if protocol 4.1
                    msg_start = 9 if len(r_body) > 9 and chr(r_body[3]) == "#" else 3
                    res.server_message = r_body[msg_start:].decode("latin-1", errors="replace")
                else:
                    res.status = "unknown"
                    res.server_message = f"Unexpected response packet type 0x{r_body[0]:02x}"

    except ConnectionRefusedError:
        res.status = "refused"
        res.error = "Connection refused on MySQL port"
    except (socket.timeout, TimeoutError):
        res.status = "timeout"
        res.error = f"MySQL probe timed out after {timeout:.1f}s"
    except Exception as exc:
        res.status = "error"
        res.error = str(exc)
    finally:
        try:
            s.close()
        except Exception:
            pass

    return res


def execute(
    target: str,
    service: str = "auto",
    port: Optional[int] = None,
    timeout: int = 5,
) -> AnonServiceResult:
    """Dispatches anonymous service probe to FTP, MySQL, or both."""
    host = normalize_host(target)
    if not host:
        return AnonServiceResult(
            target=target,
            host=host,
            error=f"Invalid target: '{target}'",
        )

    effective_timeout = max(1.0, min(float(timeout), 10.0))
    svc = (service or "auto").strip().lower()

    ftp_res: Optional[FtpResult] = None
    mysql_res: Optional[MySqlResult] = None

    if svc == "ftp" or (svc == "auto" and port == 21):
        target_port = int(port) if port else 21
        ftp_res = probe_ftp(host, port=target_port, timeout=effective_timeout)
    elif svc == "mysql" or (svc == "auto" and port == 3306):
        target_port = int(port) if port else 3306
        mysql_res = probe_mysql(host, port=target_port, timeout=effective_timeout)
    elif svc == "auto" and port is None:
        # Default auto check: probe both standard services
        ftp_res = probe_ftp(host, port=21, timeout=effective_timeout)
        mysql_res = probe_mysql(host, port=3306, timeout=effective_timeout)
    else:
        # Custom port with auto: try FTP then MySQL
        custom_port = int(port) if port else 21
        ftp_res = probe_ftp(host, port=custom_port, timeout=effective_timeout)
        if ftp_res.status == "refused":
            mysql_res = probe_mysql(host, port=custom_port, timeout=effective_timeout)

    is_vuln = bool((ftp_res and ftp_res.vulnerable) or (mysql_res and mysql_res.vulnerable))

    summary_parts = []
    if ftp_res and ftp_res.connected:
        if ftp_res.vulnerable:
            summary_parts.append(f"FTP (port {ftp_res.port}) VULNERABLE: anonymous login permitted")
        else:
            summary_parts.append(f"FTP (port {ftp_res.port}): anonymous login denied ({ftp_res.status})")
    elif ftp_res:
        summary_parts.append(f"FTP (port {ftp_res.port}): {ftp_res.status}")

    if mysql_res and mysql_res.connected:
        if mysql_res.vulnerable:
            summary_parts.append(f"MySQL (port {mysql_res.port}) VULNERABLE: empty root password accepted")
        else:
            summary_parts.append(f"MySQL (port {mysql_res.port}): authentication required (server {mysql_res.server_version}, code {mysql_res.error_code})")
    elif mysql_res:
        summary_parts.append(f"MySQL (port {mysql_res.port}): {mysql_res.status}")

    return AnonServiceResult(
        target=target,
        host=host,
        ftp=ftp_res,
        mysql=mysql_res,
        vulnerable=is_vuln,
        summary="; ".join(summary_parts),
    )
