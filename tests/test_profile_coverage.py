"""Every registered tool must end up in at least one profile
(config/profiles/*.yaml), or carry a deliberate, documented exclusion in the
'## Tools intentionally outside every profile' section of docs/profiles.md.
The reverse direction (profile -> registry) is covered by
test_profiles.py; this file closes the gap where a registered tool silently
ends up in no profile at all (the kubernetes near-miss)."""
from __future__ import annotations

import re
from pathlib import Path

import yaml

from tradecraft.tools.profiles import _PROFILES_DIR
from tradecraft.tools.registry import ALL_TOOLS

ROOT = Path(__file__).resolve().parent.parent
DOC = ROOT / "docs" / "profiles.md"
EXCLUSION_HEADING = "## Tools intentionally outside every profile"


def _registered_ids() -> set[str]:
    return {t.tool_id for t in ALL_TOOLS}


def _profile_ids() -> set[str]:
    covered: set[str] = set()
    for profile in _PROFILES_DIR.glob("*.yaml"):
        data = yaml.safe_load(profile.read_text()) or {}
        covered |= set(data.get("tool_ids") or [])
    return covered


def _documented_exclusions() -> set[str]:
    """Parses '### <tool_id>' headings under the exclusion section, stopping at
    the next '## ' heading. No exclusion heading yet means no exclusions."""
    text = DOC.read_text()
    if EXCLUSION_HEADING not in text:
        return set()
    section = text.split(EXCLUSION_HEADING, 1)[1]
    section = re.split(r"\n## ", section, maxsplit=1)[0]
    return set(re.findall(r"^### (\S+)\s*$", section, flags=re.MULTILINE))


def test_every_registered_tool_is_in_a_profile_or_documented_as_excluded():
    registered = _registered_ids()
    covered = _profile_ids() | _documented_exclusions()
    missing = sorted(registered - covered)
    assert not missing, (
        "Registered tools that appear in no profile and have no documented "
        "exclusion:\n  - " + "\n  - ".join(missing) + "\n\nFor each tool, either:\n"
        "  1. add it to every config/profiles/*.yaml it is genuinely relevant to "
        "(see docs/profiles.md, 'How to classify a tool into a profile'), or\n"
        "  2. add a '### <tool_id>' entry with a short reason under "
        f"'{EXCLUSION_HEADING}' in docs/profiles.md."
    )


def test_documented_exclusions_are_real_registered_tools():
    stale = sorted(_documented_exclusions() - _registered_ids())
    assert not stale, (
        "docs/profiles.md documents exclusions for tool ids that are not "
        f"registered in ALL_TOOLS (renamed or removed?): {stale}"
    )
