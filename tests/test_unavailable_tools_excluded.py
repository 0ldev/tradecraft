"""
Regression test for the is_available()-based exclusion in
_build_tool_map (tradecraft/execution/loop.py): a tool that can't actually
run (missing binary, missing/invalid credential -- whatever that
tool's own is_available() checks) must not appear in the tool map at
all, so its schema is never rendered to the model and it's never
offered as something the model could call.
"""
from __future__ import annotations

from tradecraft.execution.loop import _build_tool_map
from tradecraft.memory.log import EngagementMemory
from tradecraft.tools.base import Tool
from tradecraft.tools.nmap_scan import NmapScan
from tradecraft.tools.subfinder import Subfinder


def test_tool_with_false_is_available_is_excluded(monkeypatch):
    monkeypatch.setattr(Subfinder, "is_available", lambda self: False)
    memory = EngagementMemory()
    tools = _build_tool_map(memory, tool_ids=["subfinder"])
    assert "subfinder" not in tools
    # Memory/evidence tools are still present even though the only
    # requested attack tool got excluded -- they're never gated by
    # is_available() (see _build_tool_map's own docstring).
    assert "log_note" in tools
    assert "log_finding" in tools
    assert "retract_finding" in tools
    assert "read_evidence" in tools
    assert "search_evidence" in tools


def test_tool_with_true_is_available_is_kept(monkeypatch):
    monkeypatch.setattr(NmapScan, "is_available", lambda self: True)
    memory = EngagementMemory()
    tools = _build_tool_map(memory, tool_ids=["nmap_scan"])
    assert "nmap_scan" in tools


def test_excluded_tools_are_reported_to_stdout(monkeypatch, capsys):
    monkeypatch.setattr(Subfinder, "is_available", lambda self: False)
    memory = EngagementMemory()
    _build_tool_map(memory, tool_ids=["subfinder"])
    out = capsys.readouterr().out
    assert "excluded" in out
    assert "subfinder" in out


def test_no_print_when_nothing_is_excluded(monkeypatch, capsys):
    for name, cls in (("nmap_scan", NmapScan),):
        monkeypatch.setattr(cls, "is_available", lambda self: True)
    memory = EngagementMemory()
    _build_tool_map(memory, tool_ids=["nmap_scan"])
    out = capsys.readouterr().out
    assert "excluded" not in out
