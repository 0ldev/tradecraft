from unittest.mock import patch

from tradecraft.adapters.xxe_probe.execute import RawXxeResult
from tradecraft.tools.registry import ALL_TOOLS
from tradecraft.tools.xxe_probe import XxeProbe


def test_tool_identity_and_contract():
    tool = XxeProbe()
    assert tool.tool_id == "xxe_probe"
    assert tool.spec.name == "xxe_probe"
    assert tool.scope_param == "target"
    assert tool.destructive is False
    assert tool.required_binary is None
    assert any(t.tool_id == "xxe_probe" for t in ALL_TOOLS)


def test_run_forwards_params_and_returns_parsed_result():
    tool = XxeProbe()
    raw = RawXxeResult(target="https://shop.example.com/api/import", oob_domain="abc.oast.me",
                       status=200, body_snippet="ok")
    with patch("tradecraft.adapters.xxe_probe.execute.execute", return_value=raw) as ex:
        out = tool.run(target="https://shop.example.com/api/import", oob_domain="abc.oast.me", timeout=3)
    ex.assert_called_once_with(
        target="https://shop.example.com/api/import",
        oob_domain="abc.oast.me",
        content_type="application/xml",
        timeout=3,
    )
    assert out["status"] == 200
    assert "note" in out


def test_run_error_is_reported():
    tool = XxeProbe()
    raw = RawXxeResult(target="t", oob_domain="d", error="oob_domain is required")
    with patch("tradecraft.adapters.xxe_probe.execute.execute", return_value=raw):
        assert tool.run(target="t", oob_domain="") == {"target": "t", "error": "oob_domain is required"}


def test_extract_facts_is_empty():
    assert XxeProbe().extract_facts({"target": "https://x"}, {"status": 200}) == []
