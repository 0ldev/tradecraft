import hashlib
from unittest.mock import patch

from tradecraft.adapters.gowitness.execute import RawGowitnessResult
from tradecraft.execution.loop import _build_tool_map
from tradecraft.memory.evidence import EvidenceStore
from tradecraft.memory.log import EngagementMemory
from tradecraft.tools.gowitness import Gowitness


def test_gowitness_tool_run_error():
    tool = Gowitness()
    with patch("tradecraft.tools.gowitness.gowitness_execute.execute") as mock_exec:
        mock_exec.return_value = RawGowitnessResult(
            png_bytes=b"",
            final_url="https://example.com",
            error="connection refused",
        )
        res = tool.run("https://example.com")
        assert res["target"] == "https://example.com"
        assert res["error"] == "connection refused"


def test_gowitness_tool_run_success_persists_evidence(tmp_path):
    store = EvidenceStore(persist_dir=tmp_path)
    tool = Gowitness(store=store)

    fake_bytes = b"\x89PNG\r\n\x1a\ncustompngdata"
    expected_hash = hashlib.sha256(fake_bytes).hexdigest()

    with patch("tradecraft.tools.gowitness.gowitness_execute.execute") as mock_exec:
        mock_exec.return_value = RawGowitnessResult(
            png_bytes=fake_bytes,
            final_url="https://example.com/admin",
            error=None,
        )
        res = tool.run("https://example.com/admin")

        assert res["target"] == "https://example.com/admin"
        assert res["sha256"] == expected_hash
        assert res["bytes_captured"] == len(fake_bytes)
        assert "not viewable by you" in res["note"]
        assert res["evidence_id"] == "gowitness:https://example.com/admin"

        # Verify binary file exists on disk
        evidence_file = tmp_path / "example.com_admin" / "gowitness.png"
        assert evidence_file.is_file()
        assert evidence_file.read_bytes() == fake_bytes

        # Verify EvidenceStore.keys() contains the binary key
        assert "gowitness:example.com_admin" in store.keys()

        # Verify EvidenceStore.read() returns binary info
        read_res = store.read("https://example.com/admin", "gowitness")
        assert read_res["is_binary"] is True
        assert read_res["size_bytes"] == len(fake_bytes)
        assert str(evidence_file) == read_res["file_path"]

        # Tool contract hooks
        assert tool.extract_facts({"target": "https://example.com/admin"}, res) == [
            {"host": "example.com", "port": 443, "screenshot": "gowitness:https://example.com/admin"},
        ]
        assert tool.extract_evidence({"target": "https://example.com/admin"}, res) is None


def test_gowitness_extract_facts_empty_without_evidence_id():
    assert Gowitness().extract_facts({"target": "https://example.com"}, {"target": "https://example.com"}) == []


def test_gowitness_tool_loop_injection(tmp_path, monkeypatch):
    # _build_tool_map drops any tool whose is_available() is False (see
    # tradecraft/execution/loop.py) -- this test is about the loop's own
    # gowitness-instance-swap wiring, not about whether the real
    # `gowitness` binary happens to be on whatever machine runs pytest,
    # so force it available regardless.
    monkeypatch.setattr(Gowitness, "is_available", lambda self: True)
    mem = EngagementMemory()
    store = EvidenceStore(persist_dir=tmp_path)
    tools = _build_tool_map(memory=mem, evidence=store)

    assert "gowitness" in tools
    gowitness_tool = tools["gowitness"]
    assert isinstance(gowitness_tool, Gowitness)
    assert gowitness_tool._store is store
