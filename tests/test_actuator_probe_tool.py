from unittest.mock import patch

from tradecraft.adapters.actuator_probe.execute import RawActuatorResult
from tradecraft.tools.actuator_probe import ActuatorProbe
from tradecraft.tools.registry import ALL_TOOLS


def test_tool_identity_and_contract():
    tool = ActuatorProbe()
    assert tool.tool_id == "actuator_probe"
    assert tool.spec.name == "actuator_probe"
    assert tool.scope_param == "target"
    assert tool.destructive is False
    assert tool.required_binary is None
    assert any(t.tool_id == "actuator_probe" for t in ALL_TOOLS)


def test_run_forwards_params_and_returns_parsed_result():
    tool = ActuatorProbe()
    raw = RawActuatorResult(target="https://shop.example.com", results=[])
    with patch("tradecraft.adapters.actuator_probe.execute.execute", return_value=raw) as ex:
        out = tool.run(target="https://shop.example.com", timeout=5)
    ex.assert_called_once_with(target="https://shop.example.com", timeout=5)
    assert "reason" in out


def test_run_error_is_reported():
    tool = ActuatorProbe()
    raw = RawActuatorResult(target="https://shop.example.com", error="empty target")
    with patch("tradecraft.adapters.actuator_probe.execute.execute", return_value=raw):
        assert tool.run(target="https://shop.example.com") == {
            "target": "https://shop.example.com",
            "error": "empty target",
        }


def test_extract_facts_is_empty():
    assert ActuatorProbe().extract_facts({"target": "https://shop.example.com"}, {}) == []
