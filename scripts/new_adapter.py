#!/usr/bin/env python3
"""
Scaffold generator for a new Tradecraft tool: the five-piece pattern
documented in CONTRIBUTING.md's "Adding a tool" section (adapter
execute.py/parse.py, YAML contract, Tool glue, registry entry, tests),
pre-filled in the safe import shape so the generated code passes
tests/test_adapter_conventions.py on first run instead of relying on
copying `cero` correctly by hand.

Usage:
    .venv/bin/python scripts/new_adapter.py <tool_id> [--description TEXT] [--binary NAME]

Does NOT touch config/profiles/*.yaml -- profile membership is a
judgment call the author makes separately (and editing a shared profile
file is exactly where parallel-PR merge conflicts happen, so it's kept
out of this generator on purpose).
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ADAPTERS_DIR = REPO_ROOT / "tradecraft" / "adapters"
TOOLS_DIR = REPO_ROOT / "tradecraft" / "tools"
CONFIG_TOOLS_DIR = REPO_ROOT / "config" / "tools"
TESTS_DIR = REPO_ROOT / "tests"
REGISTRY_PATH = TOOLS_DIR / "registry.py"

TOOL_ID_RE = re.compile(r"^[a-z][a-z0-9_]*[a-z0-9]$")


def class_name(tool_id: str) -> str:
    return "".join(word.capitalize() for word in tool_id.split("_"))


def raw_result_name(tool_id: str) -> str:
    return f"Raw{class_name(tool_id)}Result"


def validate_tool_id(tool_id: str) -> None:
    if not TOOL_ID_RE.match(tool_id):
        sys.exit(
            f"error: '{tool_id}' is not a valid tool_id -- use lowercase "
            "snake_case (e.g. 'my_new_probe')"
        )
    adapter_dir = ADAPTERS_DIR / tool_id
    tool_glue = TOOLS_DIR / f"{tool_id}.py"
    contract = CONFIG_TOOLS_DIR / f"{tool_id}.yaml"
    for existing in (adapter_dir, tool_glue, contract):
        if existing.exists():
            sys.exit(f"error: {existing.relative_to(REPO_ROOT)} already exists")


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    print(f"  created {path.relative_to(REPO_ROOT)}")


def render_execute_py(tool_id: str) -> str:
    raw_cls = raw_result_name(tool_id)
    return f'''"""
Execution logic for {tool_id}.

TODO: describe what this adapter actually does and why, same shape as
the other tradecraft/adapters/*/execute.py module docstrings.
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class {raw_cls}:
    # TODO: raw, unparsed fields this tool produces
    lines: List[str] = field(default_factory=list)
    error: Optional[str] = None


def execute(target: str, timeout: int = 120) -> {raw_cls}:
    """Runs {tool_id} against target. TODO: build the real argv."""
    cmd = ["{tool_id}", target]  # TODO: replace with the real command line

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        return {raw_cls}(error="{tool_id} executable not found in PATH")
    except subprocess.TimeoutExpired:
        return {raw_cls}(error="{tool_id} execution timed out")

    lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    return {raw_cls}(lines=lines)
'''


def render_parse_py(tool_id: str) -> str:
    raw_cls = raw_result_name(tool_id)
    return f'''"""
Parsing logic for {tool_id} output.
Pure functions, no I/O.
"""
from __future__ import annotations

from typing import Any, Dict

from tradecraft.adapters.{tool_id}.execute import {raw_cls}


def parse_{tool_id}_result(raw: {raw_cls}) -> Dict[str, Any]:
    """TODO: turn raw.lines into clean, structured output."""
    if raw.error:
        return {{"error": raw.error}}
    return {{"lines": raw.lines}}
'''


def render_adapter_init_py(tool_id: str) -> str:
    return f'''"""
{tool_id} adapter package.
"""
from tradecraft.adapters.{tool_id}.execute import execute
from tradecraft.adapters.{tool_id}.parse import parse_{tool_id}_result

__all__ = ["execute", "parse_{tool_id}_result"]
'''


def render_tool_glue_py(tool_id: str, description: str) -> str:
    cls = class_name(tool_id)
    return f'''"""
Tool glue for {tool_id}: {description}
Glues config/tools/{tool_id}.yaml to tradecraft.adapters.{tool_id}.
"""
from __future__ import annotations

from typing import Any, Dict

from tradecraft.adapters.{tool_id}.execute import execute as {tool_id}_execute
from tradecraft.adapters.{tool_id}.parse import parse_{tool_id}_result
from tradecraft.tools.base import Tool


class {cls}(Tool):
    tool_id = "{tool_id}"

    def run(self, target: str) -> Dict[str, Any]:
        raw = {tool_id}_execute(target)
        return {{"target": target, **parse_{tool_id}_result(raw)}}
'''


def render_contract_yaml(tool_id: str, description: str, binary: str) -> str:
    return f'''tool_id: {tool_id}
required_binary: {binary}
scope_param: target

description: >
  {description}

parameters:
  type: object
  properties:
    target:
      type: string
      description: >
        TODO: describe this parameter -- test_tool_schema_completeness.py
        fails the build if this drifts from run()'s actual signature.
  required: ["target"]
'''


def render_test_py(tool_id: str) -> str:
    cls = class_name(tool_id)
    raw_cls = raw_result_name(tool_id)
    return f'''"""
Tests for {tool_id}. Mock the subprocess call in the adapter test; test
argv construction and parsing against real captured tool output, not
hand-typed fixtures -- see CONTRIBUTING.md's "Adding a tool" step 5.
"""
from __future__ import annotations

from unittest.mock import patch

from tradecraft.adapters.{tool_id}.execute import execute as {tool_id}_execute
from tradecraft.adapters.{tool_id}.parse import parse_{tool_id}_result
from tradecraft.tools.{tool_id} import {cls}


def test_execute_reports_missing_binary():
    with patch("subprocess.run", side_effect=FileNotFoundError):
        raw = {tool_id}_execute("example.com")
    assert raw.error is not None


def test_parse_passes_through_lines():
    from tradecraft.adapters.{tool_id}.execute import {raw_cls}

    raw = {raw_cls}(lines=["a", "b"])
    result = parse_{tool_id}_result(raw)
    assert result["lines"] == ["a", "b"]


def test_tool_run_shape():
    tool = {cls}()
    assert tool.tool_id == "{tool_id}"
'''


def insert_registry_entries(tool_id: str, cls: str) -> None:
    text = REGISTRY_PATH.read_text()
    lines = text.splitlines(keepends=True)

    import_re = re.compile(r"^from tradecraft\.tools\.(\w+) import \w+\n?$")
    import_line = f"from tradecraft.tools.{tool_id} import {cls}\n"

    insert_at = None
    last_import_idx = None
    for i, line in enumerate(lines):
        m = import_re.match(line)
        if not m:
            continue
        last_import_idx = i
        if insert_at is None and m.group(1) > tool_id:
            insert_at = i
    if insert_at is None:
        insert_at = (last_import_idx or 0) + 1
    lines.insert(insert_at, import_line)

    closing_bracket_idx = None
    for i, line in enumerate(lines):
        if line.strip() == "]" and i > insert_at:
            closing_bracket_idx = i
            break
    if closing_bracket_idx is None:
        sys.exit("error: could not find ALL_TOOLS closing bracket in registry.py")
    lines.insert(closing_bracket_idx, f"    {cls}(),\n")

    REGISTRY_PATH.write_text("".join(lines))
    print(f"  edited {REGISTRY_PATH.relative_to(REPO_ROOT)} (import + ALL_TOOLS entry)")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("tool_id", help="snake_case tool id, e.g. my_new_probe")
    parser.add_argument("--description", default="TODO: narrow, factual description of what this tool does.")
    parser.add_argument("--binary", default=None, help="required_binary (default: same as tool_id)")
    args = parser.parse_args()

    validate_tool_id(args.tool_id)
    tool_id = args.tool_id
    cls = class_name(tool_id)
    binary = args.binary or tool_id

    print(f"Scaffolding '{tool_id}' ({cls})...")
    write(ADAPTERS_DIR / tool_id / "__init__.py", render_adapter_init_py(tool_id))
    write(ADAPTERS_DIR / tool_id / "execute.py", render_execute_py(tool_id))
    write(ADAPTERS_DIR / tool_id / "parse.py", render_parse_py(tool_id))
    write(TOOLS_DIR / f"{tool_id}.py", render_tool_glue_py(tool_id, args.description))
    write(CONFIG_TOOLS_DIR / f"{tool_id}.yaml", render_contract_yaml(tool_id, args.description, binary))
    write(TESTS_DIR / f"test_adapters_{tool_id}.py", render_test_py(tool_id))
    insert_registry_entries(tool_id, cls)

    print(
        f"\nNext steps:\n"
        f"  1. Fill in tradecraft/adapters/{tool_id}/execute.py and parse.py.\n"
        f"  2. Fill in config/tools/{tool_id}.yaml (description, real parameters).\n"
        f"  3. Fill in tradecraft/tools/{tool_id}.py if run() takes more than 'target'.\n"
        f"  4. Fill in tests/test_adapters_{tool_id}.py against real captured output.\n"
        f"  5. Run `.venv/bin/python -m pytest -v`.\n"
        f"  6. Decide which config/profiles/*.yaml this belongs in (not done here --\n"
        f"     see 'Adding a profile' in CONTRIBUTING.md).\n"
    )


if __name__ == "__main__":
    main()
