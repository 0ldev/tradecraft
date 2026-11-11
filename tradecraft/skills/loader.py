"""
Loads every `*.md` file in this directory and concatenates them for the
system prompt. No manifest, no trigger/applicability matching -- skills
are always rendered in full. Revisit that once this directory stops
being one file and render order starts to matter for prompt-cache
stability.
"""
from __future__ import annotations

from pathlib import Path

_SKILLS_DIR = Path(__file__).resolve().parent


def render_skills() -> str:
    parts = []
    for path in sorted(_SKILLS_DIR.glob("*.md")):
        parts.append(f"### {path.stem.replace('_', ' ')}\n\n{path.read_text().strip()}")
    return "\n\n".join(parts) if parts else "(no skills loaded)"
