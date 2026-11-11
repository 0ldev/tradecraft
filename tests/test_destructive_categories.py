"""
Every tool contract that declares destructive: true must also declare a
non-empty destructive_categories list drawn from the fixed blast-radius
set in tradecraft.policy.destructive.KNOWN_CATEGORIES (see docs/policy.md).
A contract that declares destructive: true with no categories -- or an
unknown category -- is a bug: spec_loader's
load_destructive_categories() raises for the first case, and this test
catches both before they reach that runtime path.

Also covers tradecraft.policy.destructive.is_allowed's multi-category
ALL-semantics directly, and that --allow-destructive-categories actually
changes the available tool set for a real multi-category tool.
"""
from __future__ import annotations

from pathlib import Path

import yaml

from tradecraft.domain import ToolSpec
from tradecraft.execution.loop import _build_tool_map
from tradecraft.memory.log import EngagementMemory
from tradecraft.policy.destructive import KNOWN_CATEGORIES, is_allowed
from tradecraft.tools.base import Tool
from tradecraft.tools.registry import ALL_TOOLS


class _DummyMultiCategoryTool(Tool):
    """A real-config-file-free stand-in for an integration test: an actual
    registered destructive tool may need a binary that isn't installed in
    this environment (e.g. netexec), which would exclude it for
    availability reasons before the destructive gate is ever reached."""

    tool_id = "dummy_multi_category"

    @property
    def spec(self) -> ToolSpec:
        return ToolSpec(
            name="dummy_multi_category",
            description="A dummy multi-category destructive tool for testing",
            parameters={"type": "object", "properties": {}},
        )

    @property
    def required_binary(self) -> str | None:
        return None

    @property
    def scope_param(self) -> str | None:
        return None

    def is_available(self) -> bool:
        return True

    @property
    def destructive(self) -> bool:
        return True

    @property
    def destructive_categories(self) -> frozenset[str]:
        return frozenset({"code_execution", "credential_or_secret_exposure"})

    def run(self) -> dict:
        return {"result": "ran"}

ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = ROOT / "config" / "tools"


def _raw_contracts():
    for path in sorted(TOOLS_DIR.glob("*.yaml")):
        yield path, yaml.safe_load(path.read_text()) or {}


def test_every_destructive_contract_declares_categories():
    for path, data in _raw_contracts():
        if data.get("destructive", False):
            categories = data.get("destructive_categories")
            assert categories, f"{path.name} declares destructive: true but no destructive_categories"


def test_every_declared_category_is_known():
    for path, data in _raw_contracts():
        for cat in data.get("destructive_categories", []):
            assert cat in KNOWN_CATEGORIES, f"{path.name} declares unknown category {cat!r}"


def test_non_destructive_contracts_declare_no_categories():
    for path, data in _raw_contracts():
        if not data.get("destructive", False):
            assert "destructive_categories" not in data, (
                f"{path.name} is not destructive: true but declares destructive_categories"
            )


def test_is_allowed_empty_categories_always_allowed():
    assert is_allowed(frozenset(), allow_destructive=False) is True
    assert is_allowed(frozenset(), allow_destructive=False, allowed_categories=frozenset()) is True


def test_is_allowed_top_level_flag_allows_everything():
    multi = frozenset({"code_execution", "credential_or_secret_exposure"})
    assert is_allowed(multi, allow_destructive=True) is True
    assert is_allowed(multi, allow_destructive=True, allowed_categories=frozenset()) is True


def test_is_allowed_multi_category_requires_all():
    multi = frozenset({"code_execution", "credential_or_secret_exposure"})
    assert is_allowed(multi, allow_destructive=False, allowed_categories=frozenset({"code_execution"})) is False
    assert (
        is_allowed(
            multi,
            allow_destructive=False,
            allowed_categories=frozenset({"code_execution", "credential_or_secret_exposure"}),
        )
        is True
    )


def test_netexec_exploit_contract_declares_both_categories():
    """Confirms the real contract backing the integration test below
    actually spans two categories, not just the dummy stand-in."""
    data = yaml.safe_load((TOOLS_DIR / "netexec_exploit.yaml").read_text())
    assert set(data["destructive_categories"]) == {"code_execution", "credential_or_secret_exposure"}


def test_allow_destructive_categories_changes_the_available_tool_set(monkeypatch):
    dummy = _DummyMultiCategoryTool()
    monkeypatch.setattr("tradecraft.tools.registry.ALL_TOOLS", [*ALL_TOOLS, dummy])
    monkeypatch.setattr("tradecraft.execution.loop.ALL_TOOLS", [*ALL_TOOLS, dummy])

    memory = EngagementMemory()
    tools_one_category = _build_tool_map(
        memory,
        tool_ids=["dummy_multi_category"],
        allow_destructive_categories=frozenset({"code_execution"}),
    )
    assert "dummy_multi_category" not in tools_one_category

    tools_both_categories = _build_tool_map(
        memory,
        tool_ids=["dummy_multi_category"],
        allow_destructive_categories=frozenset({"code_execution", "credential_or_secret_exposure"}),
    )
    assert "dummy_multi_category" in tools_both_categories
