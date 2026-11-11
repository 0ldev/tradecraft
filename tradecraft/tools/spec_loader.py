"""
Loads a tool's model-facing contract from `config/tools/<tool_id>.yaml`.

This decouples the text the model reads (tuned like prompt content) from
the implementation, and lets a completeness check catch drift between a
tool's real parameters and what the YAML declares (see
`tests/test_tool_schema_completeness.py`). A missing or malformed YAML
file here is a loud failure (raises), not a silent skip.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

from tradecraft.domain import ToolSpec

# repo_root/config/tools/ -- config lives at the repo root, not inside
# the package, since it's operator-editable policy/prompt content, not
# code.
_CONFIG_DIR = Path(__file__).resolve().parent.parent.parent / "config" / "tools"


class ToolConfigError(Exception):
    """Raised when a tool's YAML contract is missing or malformed."""


@lru_cache(maxsize=None)
def _load_raw(tool_id: str) -> Dict[str, Any]:
    path = _CONFIG_DIR / f"{tool_id}.yaml"
    if not path.is_file():
        raise ToolConfigError(
            f"no config/tools/{tool_id}.yaml found -- every Tool must have one; "
            "there is no code-only fallback."
        )
    with open(path) as f:
        data = yaml.safe_load(f) or {}

    if data.get("tool_id") != tool_id:
        raise ToolConfigError(
            f"config/tools/{tool_id}.yaml declares tool_id={data.get('tool_id')!r}, "
            f"expected {tool_id!r} (filename and declared id must match)"
        )
    if not data.get("description", "").strip():
        raise ToolConfigError(f"config/tools/{tool_id}.yaml has no description")

    properties = data.get("parameters", {}).get("properties", {})
    for prop_name, prop_schema in properties.items():
        if not (prop_schema.get("description") or "").strip():
            raise ToolConfigError(
                f"config/tools/{tool_id}.yaml: parameter '{prop_name}' has no description"
            )
    return data


def load_spec(tool_id: str) -> ToolSpec:
    data = _load_raw(tool_id)
    parameters = data.get("parameters", {"type": "object", "properties": {}})
    properties = parameters.get("properties", {})
    stripped_properties = {
        name: {**schema, "description": schema["description"].strip()} if "description" in schema else schema
        for name, schema in properties.items()
    }
    parameters = {**parameters, "properties": stripped_properties}
    return ToolSpec(
        name=tool_id,
        description=data["description"].strip(),
        parameters=parameters,
    )


def load_required_binary(tool_id: str) -> Optional[str]:
    return _load_raw(tool_id).get("required_binary")


def load_scope_param(tool_id: str) -> Optional[str]:
    return _load_raw(tool_id).get("scope_param")


def load_destructive_flag(tool_id: str) -> bool:
    return bool(_load_raw(tool_id).get("destructive", False))


def load_destructive_categories(tool_id: str) -> frozenset[str]:
    """Blast-radius categories this tool's own contract declares under
    destructive_categories: -- empty for a non-destructive tool.

    A destructive: true tool with no (or an empty) destructive_categories
    list is a contract bug, not "no categories" -- treating it as empty
    would make tradecraft.policy.destructive.is_allowed() treat the tool as
    non-destructive and let it run unconditionally, the exact silent
    fail-open this module exists to avoid. Raise loudly instead, same
    policy as a missing YAML file."""
    raw = _load_raw(tool_id)
    categories = frozenset(raw.get("destructive_categories", []))
    if raw.get("destructive", False) and not categories:
        raise ToolConfigError(
            f"config/tools/{tool_id}.yaml declares destructive: true but no "
            "destructive_categories -- every destructive tool must declare at "
            "least one blast-radius category (see docs/policy.md)."
        )
    return categories


def declared_parameter_names(tool_id: str) -> set[str]:
    return set(_load_raw(tool_id).get("parameters", {}).get("properties", {}).keys())
