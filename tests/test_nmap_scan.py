"""
Tool-layer glue tests only. Argv construction and output parsing are
covered in test_adapters_nmap.py against the adapter directly -- this
file only checks that NmapScan wires execute()+parse() together and
surfaces the YAML-declared contract correctly.
"""
from unittest.mock import patch

from tradecraft.adapters.nmap.execute import RawScanResult
from tradecraft.tools.nmap_scan import NmapScan


def test_run_returns_parsed_ports_on_success():
    raw = RawScanResult(stdout="Host: 10.0.0.5 ()\tPorts: 22/open/tcp//ssh///\n")
    tool = NmapScan()
    with patch("tradecraft.tools.nmap_scan.nmap_execute.execute", return_value=raw):
        result = tool.run(target="10.0.0.5")

    assert "error" not in result
    assert result["ports"] == [{"port": 22, "state": "open", "protocol": "tcp", "service": "ssh"}]


def test_run_surfaces_adapter_error():
    raw = RawScanResult(error="nmap executable not found")
    tool = NmapScan()
    with patch("tradecraft.tools.nmap_scan.nmap_execute.execute", return_value=raw):
        result = tool.run(target="10.0.0.5")

    assert result["error"] == "nmap executable not found"
    assert result["ports"] == []


def test_contract_loaded_from_yaml():
    tool = NmapScan()
    assert tool.spec.name == "nmap_scan"
    assert tool.required_binary == "nmap"
    assert tool.scope_param == "target"
    assert "target" in tool.spec.parameters["properties"]


def test_is_available_checks_for_binary():
    tool = NmapScan()
    with patch("shutil.which", return_value=None):
        assert tool.is_available() is False
    with patch("shutil.which", return_value="/usr/bin/nmap"):
        assert tool.is_available() is True
