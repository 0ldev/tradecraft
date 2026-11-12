"""Plugin SDK scaffold generator (Tradecraft 2.0, Phase 5).

`tradecraft new-tool <tool_id>` generates every file a working tool
needs, following the one-place-per-fact convention the project already
enforces:

    config/tools/<id>.yaml      the model-facing contract
    tradecraft/adapters/<id>/   execute.py (subprocess) + parse.py (pure)
    tradecraft/tools/<id>.py    the Tool subclass gluing both together
    tests/test_<id>.py          a runnable starting test

Registration in `tradecraft/tools/registry.py` is deliberately manual
(one import + one ALL_TOOLS line) -- the generator prints the exact
lines instead of editing a hand-curated file behind the contributor's
back.
"""
from __future__ import annotations

import re
from pathlib import Path

_TOOL_ID_RE = re.compile(r"^[a-z][a-z0-9_]{1,48}$")

_YAML_TEMPLATE = """name: {tool_id}
description: >-
  {class_name}: TODO one factual sentence the model reads when deciding
  whether to call this tool. State what it does and when to prefer it;
  cross-tool guidance belongs in tradecraft/skills/, not here.
required_binary: {binary}
scope_param: {scope_param}
destructive: false
# destructive_categories: []  # only when destructive: true -- see docs/policy.md
parameters:
  type: object
  properties:
    {scope_param}:
      type: string
      description: Target to test, e.g. 10.0.0.5:80 or https://target.local
  required:
    - {scope_param}
"""

_EXECUTE_TEMPLATE = '''"""Subprocess execution for the {tool_id} adapter.

One job: run the real binary with safe, explicit arguments and return
raw output. All parsing lives in parse.py -- pure and unit-testable.
"""
from __future__ import annotations

import shutil
import subprocess
from typing import Dict, Union


def run(params: Dict[str, object], timeout: int = 300) -> Dict[str, Union[str, int]]:
    """Runs `{binary}` against the target. Returns raw stdout/stderr plus
    the exit code; parse.py turns that into structured results."""
    binary = shutil.which("{binary}")
    if binary is None:
        return {{"error": "binary not found on PATH: {binary}"}}

    target = str(params.get("{scope_param}", "")).strip()
    if not target:
        return {{"error": "missing required parameter '{scope_param}'"}}

    try:
        proc = subprocess.run(
            [binary, target],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {{"error": "{tool_id} timed out after {{}}s".format(timeout)}}

    return {{
        "exit_code": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }}
'''

_PARSE_TEMPLATE = '''"""Pure parsing for the {tool_id} adapter: raw subprocess output ->
structured dict. No I/O here by convention, so it stays unit-testable
without the binary installed."""
from __future__ import annotations

from typing import Any, Dict, Union


def parse(raw: Dict[str, Union[str, int]]) -> Dict[str, Any]:
    if raw.get("error"):
        return {{"error": raw["error"]}}
    stdout = raw.get("stdout") or ""
    # TODO: real parsing. Start honest and narrow: report whether the
    # run succeeded and hand the model the most useful lines, not the
    # whole transcript (that belongs in the EvidenceStore).
    return {{
        "result": "completed" if raw.get("exit_code") == 0 else "nonzero_exit",
        "lines": [ln for ln in stdout.splitlines() if ln.strip()][:50],
    }}
'''

_TOOL_TEMPLATE = '''"""Tool glue for {tool_id}: YAML contract + adapter, one Tool.run()."""
from __future__ import annotations

from typing import Any, Dict, List

from tradecraft.tools.base import Tool


class {class_name}(Tool):
    tool_id = "{tool_id}"

    def run(self, **params: Any) -> Dict[str, Any]:
        from tradecraft.adapters.{tool_id}.execute import run as execute
        from tradecraft.adapters.{tool_id}.parse import parse

        return parse(execute(params))

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """TODO: report deterministic (host, port) facts when this tool
        has per-target data. Parse the scope_param into host/port; return
        [] when the result carries none."""
        return []
'''

_TEST_TEMPLATE = '''"""Starter tests for the {tool_id} tool (pure parts only).

Self-contained by design: loads the scaffolded modules directly from
their file paths, so the starter suite passes in a fresh scaffold
before the tool is registered in the registry."""
import importlib.util
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def _load(name, relpath):
    spec = importlib.util.spec_from_file_location(name, ROOT / relpath)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_parse_handles_error():
    parse = _load("demo_parse", "tradecraft/adapters/{tool_id}/parse.py").parse
    assert parse({{"error": "binary not found on PATH: nope"}}) == {{"error": "binary not found on PATH: nope"}}


def test_parse_extracts_lines():
    parse = _load("demo_parse", "tradecraft/adapters/{tool_id}/parse.py").parse
    result = parse({{"exit_code": 0, "stdout": "line1\\nline2\\n", "stderr": ""}})
    assert result["result"] == "completed"
    assert result["lines"] == ["line1", "line2"]


def test_tool_contract_loads():
    contract = yaml.safe_load((ROOT / "config" / "tools" / "{tool_id}.yaml").read_text())
    assert contract["name"] == "{tool_id}"
    assert contract["scope_param"]
    # Replace with a subprocess-free run() test once the adapter is real.
'''


def validate_tool_id(tool_id: str) -> str:
    if not _TOOL_ID_RE.match(tool_id or ""):
        raise ValueError(
            f"invalid tool id '{tool_id}' -- use lowercase [a-z0-9_], "
            "starting with a letter (e.g. tls_expiry_probe)"
        )
    return tool_id


def scaffold(tool_id: str, root: str | Path = ".") -> list:
    """Writes the four scaffolds under `root` (repo checkout). Returns
    the created paths. Existing files are never overwritten."""
    validate_tool_id(tool_id)
    root = Path(root)
    class_name = "".join(part.capitalize() for part in tool_id.split("_"))

    files = {
        root / "config" / "tools" / f"{tool_id}.yaml": _YAML_TEMPLATE.format(
            tool_id=tool_id, class_name=class_name, binary="TODO_BINARY", scope_param="target",
        ),
        root / "tradecraft" / "adapters" / tool_id / "__init__.py": "",
        root / "tradecraft" / "adapters" / tool_id / "execute.py": _EXECUTE_TEMPLATE.format(
            tool_id=tool_id, binary="TODO_BINARY", scope_param="target",
        ),
        root / "tradecraft" / "adapters" / tool_id / "parse.py": _PARSE_TEMPLATE.format(tool_id=tool_id),
        root / "tradecraft" / "tools" / f"{tool_id}.py": _TOOL_TEMPLATE.format(
            tool_id=tool_id, class_name=class_name,
        ),
        root / "tests" / f"test_{tool_id}.py": _TEST_TEMPLATE.format(tool_id=tool_id, class_name=class_name),
    }
    for path, content in files.items():
        if path.exists():
            raise FileExistsError(f"refusing to overwrite existing file: {path}")
    created = []
    for path, content in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        created.append(path)
    return created


def registration_snippet(tool_id: str) -> str:
    class_name = "".join(part.capitalize() for part in tool_id.split("_"))
    return (
        f"\nAdd to tradecraft/tools/registry.py:\n\n"
        f"    from tradecraft.tools.{tool_id} import {class_name}\n"
        f"    # then append {class_name}() to the ALL_TOOLS list\n"
    )
