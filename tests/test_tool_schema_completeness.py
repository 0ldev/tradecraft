"""
Every parameter a Tool's run() actually accepts must be declared (with a
real description) in its config/tools/<id>.yaml, and vice versa -- no
parameter the model is told about that run() silently ignores, and no
parameter run() reads that the model was never told exists.
"""
import inspect

from tradecraft.memory.cross_engagement import CrossEngagementMemory
from tradecraft.memory.evidence import EvidenceStore
from tradecraft.memory.log import EngagementMemory
from tradecraft.tools.base import Tool
from tradecraft.tools.evidence_tools import ReadEvidence, SearchEvidence
from tradecraft.tools.memory_tools import LogFinding, LogNote, RecallMemory, RetractFinding
from tradecraft.tools.registry import ALL_TOOLS
from tradecraft.tools.spec_loader import declared_parameter_names, load_destructive_flag


def _runtime_param_names(tool: Tool) -> set[str]:
    sig = inspect.signature(tool.run)
    return {name for name in sig.parameters if name != "self"}


def _all_tools_for_test() -> list[Tool]:
    memory = EngagementMemory()
    evidence = EvidenceStore()
    return [
        *ALL_TOOLS,
        LogNote(memory),
        LogFinding(memory),
        RetractFinding(memory),
        RecallMemory(store=CrossEngagementMemory(db_path=":memory:")),
        ReadEvidence(evidence),
        SearchEvidence(evidence),
    ]


def test_every_tool_param_is_declared_and_described():
    for tool in _all_tools_for_test():
        declared = declared_parameter_names(tool.tool_id)
        runtime = _runtime_param_names(tool)
        assert runtime == declared, (
            f"{tool.tool_id}: run() params {runtime} != "
            f"config/tools/{tool.tool_id}.yaml declared params {declared}"
        )


def test_every_tool_has_a_spec_and_nonempty_description():
    for tool in _all_tools_for_test():
        assert tool.spec.name == tool.tool_id
        assert tool.spec.description.strip()


def test_every_tool_has_destructive_boolean_property():
    for tool in _all_tools_for_test():
        assert isinstance(tool.destructive, bool)


def test_destructive_tool_schema_completeness(tmp_path, monkeypatch):
    """Asserts that a tool with destructive: true declared in its contract
    must follow the exact same schema completeness rules as any other tool."""
    yaml_content = """tool_id: dummy_destructive_contract
destructive: true
description: "A destructive tool that mutates target state."
parameters:
  type: object
  properties:
    target:
      type: string
      description: "Target address"
    payload:
      type: string
      description: "Payload string"
  required:
    - target
"""
    contract_file = tmp_path / "dummy_destructive_contract.yaml"
    contract_file.write_text(yaml_content)

    monkeypatch.setattr("tradecraft.tools.spec_loader._CONFIG_DIR", tmp_path)
    assert load_destructive_flag("dummy_destructive_contract") is True

    class DummyDestructiveContractTool(Tool):
        tool_id = "dummy_destructive_contract"

        def run(self, target: str, payload: str):
            return {"target": target, "payload": payload}

    tool = DummyDestructiveContractTool()
    assert tool.destructive is True
    assert tool.spec.name == "dummy_destructive_contract"
    assert tool.spec.description.strip()
    assert _runtime_param_names(tool) == declared_parameter_names(tool.tool_id)
