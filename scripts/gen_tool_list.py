#!/usr/bin/env python3
"""
Regenerates docs/tool-list.md from the registry/contracts/profiles --
the one authoritative place every registered tool, its destructive
status, and its profile membership is listed for a reader (rather than
having to open 170 individual config/tools/*.yaml files).

Usage:
    .venv/bin/python scripts/gen_tool_list.py

Run this whenever a tool is added/removed/reclassified;
tests/test_tool_list_coverage.py fails the build if docs/tool-list.md
drifts from the registry.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from tradecraft.tools.profiles import list_profiles, load_profile  # noqa: E402
from tradecraft.tools.registry import ALL_TOOLS  # noqa: E402
from tradecraft.tools.spec_loader import load_destructive_flag  # noqa: E402

OUT_PATH = REPO_ROOT / "docs" / "tool-list.md"


def first_sentence(text: str) -> str:
    collapsed = re.sub(r"\s+", " ", text).strip()
    match = re.search(r"(.+?\.)(\s|$)", collapsed)
    return match.group(1) if match else collapsed


def main() -> None:
    profile_names = [p for p in list_profiles() if p != "full"]
    membership: dict[str, list[str]] = {}
    for profile in profile_names:
        for tool_id in load_profile(profile):
            membership.setdefault(tool_id, []).append(profile)

    rows = []
    for tool in sorted(ALL_TOOLS, key=lambda t: t.tool_id):
        tool_id = tool.tool_id
        desc = first_sentence(tool.spec.description)
        destructive = "yes" if load_destructive_flag(tool_id) else ""
        profiles = ", ".join(sorted(membership.get(tool_id, []))) or "*(none)*"
        rows.append((tool_id, destructive, profiles, desc))

    lines = [
        "# Tool list",
        "",
        "Every registered tool, generated from `tradecraft/tools/registry.py`,",
        "`config/tools/*.yaml`, and `config/profiles/*.yaml` -- regenerate with",
        "`.venv/bin/python scripts/gen_tool_list.py` after adding/removing/reclassifying",
        "a tool. `tests/test_tool_list_coverage.py` fails the build if this drifts",
        "from the registry. See [`tools.md`](tools.md) for how a tool is built and",
        "[`profiles.md`](profiles.md) for what a profile is.",
        "",
        f"{len(rows)} tools across {len(profile_names)} profiles "
        f"({sum(1 for r in rows if r[1])} destructive).",
        "",
        "| Tool | Destructive | Profiles | Description |",
        "|---|---|---|---|",
    ]
    for tool_id, destructive, profiles, desc in rows:
        desc = desc.replace("|", "\\|")
        lines.append(f"| `{tool_id}` | {destructive} | {profiles} | {desc} |")
    lines.append("")

    OUT_PATH.write_text("\n".join(lines))
    print(f"wrote {len(rows)} tools to {OUT_PATH.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
