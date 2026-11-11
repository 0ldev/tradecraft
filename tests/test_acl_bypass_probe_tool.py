from unittest.mock import patch

from tradecraft.adapters.acl_bypass_probe.execute import RawAclBypassResult, VariantAttempt
from tradecraft.tools.acl_bypass_probe import AclBypassProbe
from tradecraft.tools.registry import ALL_TOOLS


def test_tool_identity_and_contract():
    tool = AclBypassProbe()
    assert tool.tool_id == "acl_bypass_probe"
    assert tool.spec.name == "acl_bypass_probe"
    assert tool.scope_param == "target"
    assert tool.destructive is False
    assert tool.required_binary is None
    assert any(t.tool_id == "acl_bypass_probe" for t in ALL_TOOLS)


def test_run_passes_target_and_timeout_to_adapter_and_returns_parsed_result():
    tool = AclBypassProbe()
    raw = RawAclBypassResult(
        target="https://example.com/admin",
        baseline_status=403,
        baseline_length=146,
        baseline_was_blocked=True,
        attempts=[
            VariantAttempt("trailing_slash", "https://example.com/admin/", None, 200, 2048),
        ],
    )
    with patch("tradecraft.adapters.acl_bypass_probe.execute.execute", return_value=raw) as ex:
        out = tool.run(target="https://example.com/admin", timeout=4)
    ex.assert_called_once_with(target="https://example.com/admin", timeout=4)
    assert out["bypasses"][0]["label"] == "trailing_slash"
    assert out["bypasses"][0]["url_or_header"] == "https://example.com/admin/"


def test_run_error_is_reported():
    tool = AclBypassProbe()
    raw = RawAclBypassResult(target="https://example.com/admin", error="Connection refused")
    with patch("tradecraft.adapters.acl_bypass_probe.execute.execute", return_value=raw):
        out = tool.run(target="https://example.com/admin")
    assert out == {"target": "https://example.com/admin", "error": "Connection refused"}


def test_extract_facts_is_empty():
    tool = AclBypassProbe()
    assert tool.extract_facts({"target": "https://example.com/admin"}, {"bypasses": []}) == []
