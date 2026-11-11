"""
Domain types: the pure data shapes shared across layers. Nothing here
does I/O (no subprocess, no network, no filesystem).

Dependency direction for the whole package: domain <- adapters <- tools
<- execution <- cli. An inner layer never imports an outer one (domain
imports nothing from this package; adapters only import domain; tools
import domain + adapters; execution imports all of the above). If you
find yourself importing `tradecraft.execution` from `tradecraft.adapters`, the
layering has already broken.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict


@dataclass(frozen=True)
class ToolSpec:
    """What the model sees for one tool: name, description, and a JSON
    Schema for its parameters. Kept narrow and factual by convention --
    see docs/tools.md's "Skills vs. tool descriptions" section.
    Strategic/cross-tool guidance belongs in tradecraft/skills/, not here."""

    name: str
    description: str
    parameters: Dict[str, Any]
