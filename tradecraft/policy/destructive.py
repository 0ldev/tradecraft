"""
Destructive-tool gate -- whether a tool whose own contract declares
destructive: true is allowed to run in this engagement. Pure, no I/O,
no dependency on anything else in this project. Mirrors the shape the
old (removed) scope.py gate had, minus the part that never actually
enforced anything.

A destructive tool also declares destructive_categories: a non-empty
set of blast-radius categories (see docs/policy.md for the fixed list and what each one means).
--allow-destructive is the original, coarse on/off switch: it allows
every destructive tool regardless of category. --allow-destructive-categories
is the finer-grained alternative: a tool is allowed only if ALL of its
declared categories are in the operator's opt-in set. A tool spanning
more than one category (e.g. code_execution + credential exposure)
needs every one of them opted into -- opting into just one category a
multi-category tool happens to have is not enough.
"""
from __future__ import annotations

KNOWN_CATEGORIES = frozenset({
    "account_lockout_risk",
    "state_mutation",
    "code_execution",
    "credential_or_secret_exposure",
    "persistent_artifact",
    "availability_risk",
})


def is_allowed(
    categories: frozenset[str],
    allow_destructive: bool,
    allowed_categories: frozenset[str] = frozenset(),
) -> bool:
    """A tool with no categories (non-destructive) is always allowed.
    allow_destructive=True allows every destructive tool regardless of
    category -- the original, unchanged top-level switch. Otherwise a
    destructive tool is allowed only if every one of its categories is
    in allowed_categories."""
    if not categories:
        return True
    if allow_destructive:
        return True
    return categories <= allowed_categories
