"""
Wordlist resolution for adapters (ffuf, etc.).

Path resolution must not depend on the process's current working directory.
Resolution order:
1. Bundled copy in config/wordlists/ matching the given name's basename (with or without .txt)
2. Exact file path if it exists on disk
3. Bundled fallback file (defaults to common.txt)
"""
from __future__ import annotations

import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
WORDLISTS_DIR = PROJECT_ROOT / "config" / "wordlists"


def resolve_wordlist(name: str, fallback: str = "common.txt") -> str:
    """Resolve a wordlist name or path to a real file path."""
    if not name:
        name = fallback
    basename = os.path.basename(name)
    # 1. Direct match in bundled directory
    if (WORDLISTS_DIR / basename).is_file():
        return str(WORDLISTS_DIR / basename)
    # 2. If no extension given, check .kite, .json, or .txt in bundled directory
    if "." not in basename:
        for ext in (".kite", ".json", ".txt"):
            candidate = WORDLISTS_DIR / f"{basename}{ext}"
            if candidate.is_file():
                return str(candidate)
        basename += ".txt"
    bundled = WORDLISTS_DIR / basename
    if bundled.is_file():
        return str(bundled)
    # 3. Exact path on disk
    if os.path.isfile(name):
        return name
    # 4. Fallback file in bundled directory
    return str(WORDLISTS_DIR / fallback)


def read_wordlist_lines(path: str) -> list[str]:
    """Reads a wordlist file into a list of stripped, non-empty lines.

    For an adapter that needs the actual candidate list in Python (to
    bound/cap it, e.g. hydra), not just a file path to hand to the
    external binary (e.g. ffuf/kerbrute's own argv)."""
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]
