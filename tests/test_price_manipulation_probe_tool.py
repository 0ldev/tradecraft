"""Unit tests for the price_manipulation_probe tool layer."""
from __future__ import annotations

from unittest.mock import patch

from tradecraft.adapters.price_manipulation_probe.execute import RawPriceManipulationResult
from tradecraft.tools.price_manipulation_probe import PriceManipulationProbe


def test_tool_attributes():
    tool = PriceManipulationProbe()
    assert tool.tool_id == "price_manipulation_probe"
    assert tool.scope_param == "target"
    assert tool.destructive is True


def test_run_error_is_reported():
    tool = PriceManipulationProbe()
    failed = RawPriceManipulationResult(target="https://shop.example.com", error="at least one of price_param/quantity_param is required")
    with patch("tradecraft.tools.price_manipulation_probe.pmp_execute.execute", return_value=failed):
        result = tool.run(target="https://shop.example.com", body="{}")
    assert "error" in result


def test_extract_facts_only_on_confirmed_accept():
    tool = PriceManipulationProbe()
    params = {"target": "https://shop.example.com/cart/1"}
    confirmed_result = {
        "target": "https://shop.example.com/cart/1",
        "confirmed_accepted": 1,
        "attempts": [{"variant": "price_zero", "classification": "accepted_confirmed"}],
    }
    facts = tool.extract_facts(params, dict(confirmed_result))
    assert len(facts) == 1
    assert facts[0]["host"] == "shop.example.com"
    assert "price_zero" in facts[0]["vulnerability"]
    assert facts[0]["severity"] == "high"

    unconfirmed_result = {"target": "https://shop.example.com/cart/1", "confirmed_accepted": 0, "attempts": []}
    assert tool.extract_facts(params, unconfirmed_result) == []
    assert tool.extract_facts(params, {"error": "boom"}) == []
