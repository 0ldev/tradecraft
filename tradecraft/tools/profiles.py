"""Engagement-shape profiles: named, curated, OVERLAPPING tool_id
lists an operator selects before the loop starts (--profile), same
one-way "operator decides upfront" shape as --tools and the old scope
file. A tool can legitimately appear in more than one profile -- these
are not a partition, they're presets."""
from __future__ import annotations

from pathlib import Path
from typing import List

import yaml

_PROFILES_DIR = Path(__file__).resolve().parent.parent.parent / "config" / "profiles"


class ProfileError(Exception):
    """Unknown or malformed profile -- a loud failure, not a silent skip,
    same convention config/tools/*.yaml already uses."""


def load_profile(name: str) -> List[str]:
    """Loads tool_ids for a named profile. 'full' returns every registered tool."""
    if name == "full":
        from tradecraft.tools.registry import ALL_TOOLS

        return [t.tool_id for t in ALL_TOOLS]

    path = _PROFILES_DIR / f"{name}.yaml"
    if not path.is_file():
        raise ProfileError(
            f"no config/profiles/{name}.yaml found -- known profiles are "
            f"the files in config/profiles/ plus the built-in 'full'."
        )
    data = yaml.safe_load(path.read_text()) or {}
    tool_ids = data.get("tool_ids")
    if not tool_ids:
        raise ProfileError(f"config/profiles/{name}.yaml declares no tool_ids")
    return list(tool_ids)


def list_profiles() -> List[str]:
    """Returns sorted list of available profile names including 'full'."""
    names = [p.stem for p in _PROFILES_DIR.glob("*.yaml")]
    if "full" not in names:
        names.append("full")
    return sorted(names)
