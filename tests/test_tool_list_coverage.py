"""docs/tool-list.md is generated (scripts/gen_tool_list.py) from
ALL_TOOLS, so it must list every registered tool and nothing else --
this closes the gap a forgotten regeneration after adding/removing a
tool would otherwise leave silently stale, same convention
test_profile_coverage.py and test_wordlist_consistency.py already use."""
from __future__ import annotations

import re
from pathlib import Path

from tradecraft.tools.registry import ALL_TOOLS

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "tool-list.md"


def _registered_ids() -> set[str]:
    return {t.tool_id for t in ALL_TOOLS}


def _listed_ids() -> set[str]:
    text = DOC.read_text()
    return set(re.findall(r"^\| `(\S+)` \|", text, flags=re.MULTILINE))


def test_every_registered_tool_is_listed():
    missing = sorted(_registered_ids() - _listed_ids())
    assert not missing, (
        "Registered tools missing from docs/tool-list.md (run "
        "`.venv/bin/python scripts/gen_tool_list.py` to regenerate):\n  - "
        + "\n  - ".join(missing)
    )


def test_listed_tools_are_all_registered():
    stale = sorted(_listed_ids() - _registered_ids())
    assert not stale, (
        "docs/tool-list.md lists ids that are not registered in ALL_TOOLS "
        "(renamed or removed? run `.venv/bin/python scripts/gen_tool_list.py` "
        f"to regenerate): {stale}"
    )
