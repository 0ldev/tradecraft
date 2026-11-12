"""Dynamic tool menu (Tradecraft 2.0, Phase 1).

The old behavior sent the full JSON parameter schema of every available
tool to the model on EVERY turn. With a large profile that's tens of
thousands of tokens burned per turn on schemas the model mostly won't
call -- and every extra schema is also one more candidate the model can
mis-select.

The menu replaces that with two tiers:

1. The MENU -- one compact line per tool (name + first sentence of its
   description), rendered into the per-turn state message. Cheap, and
   always complete: the model can see everything that exists.
2. LOADED schemas -- full JSON parameter schemas, sent via `tools=`,
   only for tools the model has activated with the `load_tool`
   meta-tool (plus a small always-on set: the memory/evidence tools and
   `load_tool` itself).

`load_tool` validates the name against the (already filtered) tool map,
flips the tool into the active set, and returns its full parameter
schema as the tool result -- so the very next turn the model can call
it with correct arguments. Activation is permanent for the engagement;
nothing is ever silently unloaded.

When the available tool count is small (profiles like `web`), sending
all schemas is genuinely fine and saves a turn -- the menu engages only
past a threshold, overridable via TRADECRAFT_DYNAMIC_MENU.
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Set

from tradecraft.tools.base import Tool

# Below this many available tools, sending every schema is cheaper (in
# tokens AND turns) than making the model load them one by one.
MENU_THRESHOLD = 40

# Tools that must always have their full schema loaded, menu or not.
ALWAYS_ON_TOOLS = frozenset({
    "load_tool",
    "log_note",
    "log_finding",
    "retract_finding",
    "recall_memory",
    "read_evidence",
    "search_evidence",
})


def dynamic_menu_enabled(tool_count: int) -> bool:
    env = os.environ.get("TRADECRAFT_DYNAMIC_MENU", "").strip().lower()
    if env in ("0", "false", "off", "no"):
        return False
    if env in ("1", "true", "on", "yes"):
        return True
    return tool_count > MENU_THRESHOLD


def _first_sentence(description: str) -> str:
    text = (description or "").strip()
    if not text:
        return "(no description)"
    for i, ch in enumerate(text):
        if ch in ".!?\n":
            return text[: i + 1].strip()
    return text


def build_tool_menu(tool_map: Dict[str, Tool]) -> str:
    """Compact one-line-per-tool menu for the state message. Grouped by
    nothing fancy -- plain alphabetical, since the model's job here is
    lookup, not browsing."""
    if not tool_map:
        return "(no tools available)"
    lines = []
    for name in sorted(tool_map):
        tool = tool_map[name]
        desc = getattr(tool.spec, "description", "") or ""
        lines.append(f"- {name}: {_first_sentence(desc)}")
    return "\n".join(lines)


class LoadTool(Tool):
    """Meta-tool: activates a menu-listed tool's full schema for the rest
    of the engagement. Bound to the live tool map and the mutable active
    set in execution/loop.py -- same construction pattern as LogNote and
    friends (built per-run, not part of the static registry)."""

    tool_id = "load_tool"

    def __init__(self, tool_map: Dict[str, Tool], active: Set[str]):
        self.tool_map = tool_map
        self.active = active

    def run(self, tool_name: str) -> Dict[str, Any]:
        name = (tool_name or "").strip()
        if name not in self.tool_map:
            available = ", ".join(sorted(self.tool_map))
            return {
                "error": f"unknown tool '{name}'. Available tools: {available}",
            }
        if name in ALWAYS_ON_TOOLS:
            return {"loaded": True, "note": f"{name} is always active -- schema already loaded."}
        self.active.add(name)
        schema = openai_schema(self.tool_map[name])
        return {
            "loaded": name,
            "schema": schema,
            "note": (
                f"{name} is now active with its full parameter schema (above). "
                "Its schema is included in tools= from your next turn on."
            ),
        }


def openai_schema(tool: Tool) -> Dict[str, Any]:
    """One tool's OpenAI-style function schema -- the same shape
    registry.openai_tool_schemas renders, for a single tool."""
    spec = tool.spec
    return {
        "type": "function",
        "function": {
            "name": spec.name,
            "description": spec.description,
            "parameters": spec.parameters,
        },
    }


def schemas_for(
    tool_map: Dict[str, Tool],
    active: Set[str],
) -> List[Dict[str, Any]]:
    """Full schemas for: always-on tools present in the map + every tool
    the model has activated. Unknown names in `active` are ignored
    (defensive -- tools can't disappear mid-run, but a stale set from a
    caller shouldn't crash the loop)."""
    names = (set(active) | ALWAYS_ON_TOOLS) & set(tool_map)
    return [openai_schema(tool_map[name]) for name in sorted(names)]
