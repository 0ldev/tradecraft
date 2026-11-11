import subprocess
from unittest.mock import patch

from tradecraft.adapters.nmap import execute as nmap_execute
from tradecraft.adapters.nmap import parse as nmap_parse


def _fake_process(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


# -- parse.py: pure, no subprocess involved -------------------------------


def test_parses_open_ports_from_grepable_output():
    grepable = (
        "Host: 10.0.0.5 ()\tPorts: 22/open/tcp//ssh///, 80/open/tcp//http///, "
        "81/closed/tcp//http///\n"
    )
    ports = nmap_parse.parse_open_ports(grepable)

    assert {"port": 22, "state": "open", "protocol": "tcp", "service": "ssh"} in ports
    assert {"port": 80, "state": "open", "protocol": "tcp", "service": "http"} in ports
    assert all(p["port"] != 81 for p in ports)


def test_parse_handles_no_open_ports_as_empty_list_not_error():
    assert nmap_parse.parse_open_ports("") == []


def test_parse_extracts_version_strings():
    """Regression test: nmap's grepable output carries a version string
    right after `service`, and it must not be dropped."""
    grepable = (
        "Host: 192.168.15.26 ()\tPorts: 21/open/tcp//ftp//vsftpd 3.0.3/, "
        "22/open/tcp//ssh//OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)/, "
        "80/open/tcp//http//nginx 1.22.1/\n"
    )
    ports = nmap_parse.parse_open_ports(grepable)

    by_port = {p["port"]: p for p in ports}
    assert by_port[21]["version"] == "vsftpd 3.0.3"
    assert by_port[22]["version"] == "OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)"
    assert by_port[80]["version"] == "nginx 1.22.1"


def test_parse_omits_version_key_when_nmap_reports_none():
    grepable = "Host: 10.0.0.5 ()\tPorts: 22/open/tcp//ssh///\n"
    ports = nmap_parse.parse_open_ports(grepable)
    assert "version" not in ports[0]


def test_parse_does_not_leak_ignored_state_trailer_into_version():
    """Regression test: nmap appends a sibling 'Ignored State: ...' tab
    field whenever a scan has any closed ports -- true of nearly every
    real scan -- and it must not leak into the last port's version
    string."""
    grepable = (
        "Host: 192.168.15.26 ()\tPorts: 21/open/tcp//ftp//vsftpd 3.0.3/, "
        "80/open/tcp//http//nginx 1.22.1/\tIgnored State: closed (997)\n"
    )
    ports = nmap_parse.parse_open_ports(grepable)

    by_port = {p["port"]: p for p in ports}
    assert by_port[80]["version"] == "nginx 1.22.1"
    assert "Ignored State" not in by_port[80]["version"]


# -- execute.py: argv construction + subprocess handling -------------------


def test_explicit_port_in_target_pins_scan():
    argv, host = nmap_execute.build_argv("10.0.0.5:8080")
    assert "-p" in argv and "8080" in argv
    assert host == "10.0.0.5"


def test_quick_depth_uses_fast_flag():
    argv, _ = nmap_execute.build_argv("10.0.0.5", depth="quick")
    assert "-F" in argv


def test_standard_depth_uses_version_detection():
    argv, _ = nmap_execute.build_argv("10.0.0.5", depth="standard")
    assert "-sV" in argv and "--top-ports" in argv


def test_nonzero_exit_is_reported_as_error_not_empty_success():
    with patch("subprocess.run", return_value=_fake_process(1, "", "permission denied")):
        result = nmap_execute.execute("10.0.0.5")
    assert result.error is not None


def test_missing_binary_is_reported_cleanly():
    with patch("subprocess.run", side_effect=FileNotFoundError()):
        result = nmap_execute.execute("10.0.0.5")
    assert result.error == "nmap executable not found"


def test_timeout_is_reported_cleanly():
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="nmap", timeout=300)):
        result = nmap_execute.execute("10.0.0.5")
    assert "timed out" in result.error
