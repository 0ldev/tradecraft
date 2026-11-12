"""Deterministic next-action suggestions (Tradecraft 2.0, Phase 1).

Generalizes the two hardcoded mid-loop nudges (`_has_open_injection_thread`
and `_has_open_interactsh_thread` in execution/loop.py) into a small,
pure rules engine that reads the FactStore and proposes concrete next
tool calls.

Design stance, matching the project's own philosophy (see docs/policy.md
and the memory module docstrings): the harness may PROPOSE, the model
decides. Nothing here blocks a tool call, forces a turn, or claims
authority it doesn't have -- the suggestions land in the per-turn state
message as advisory text, and each one carries the deterministic reason
it fired so the model can dismiss it with a reason instead of obeying
blindly. The value is that the cheapest, most mechanical half of "what
should I run next" never has to be re-derived by the model from raw
FACTS lines every turn.
"""
from __future__ import annotations

from typing import Any, Dict, List

# Parameter-discovery fact fields, and the injection-class tested fields
# that indicate some probe followed through on them (same field list the
# loop's injection-thread nudge uses -- kept in sync deliberately).
_DISCOVERY_FIELDS = ("arjun_params_discovered", "params_discovered")
_INJECTION_TESTED_FIELDS = (
    "sqli_tested",
    "sqli_injectable",
    "xss_tested",
    "cmdi_tested",
    "open_redirect_tested",
    "ssrf_tested",
    "nosql_tested",
    "nosql_vulnerable",
    "crlf_tested",
    "crlf_vulnerable",
    "arjun_tested",
)

# Port heuristics for "this looks like an HTTP service worth parameter-
# discovering": any record with an http_title/web tech field, regardless
# of port number (services hide on odd ports on purpose).
_HTTP_HINT_FIELDS = ("http_title", "web_servers", "tech_stack", "http_server")


def suggest_next_actions(
    records: List[Any],
) -> List[Dict[str, str]]:
    """records: FactStore.sorted_records() output.

    Returns an ordered list of {tool_id, target, reason} dicts. Ordered
    by how cheap-and-foundational each action is: discovery before
    exploitation, dense targets before sparse ones.
    """
    actions: List[Dict[str, str]] = []

    for (host, port), record in records:
        target = f"{host}:{port}"

        discovered = next(
            (record.get(f) for f in _DISCOVERY_FIELDS if record.get(f)), None
        )
        tested_any_injection = any(record.get(f) for f in _INJECTION_TESTED_FIELDS)

        # Rule 1: parameters found, no injection probe followed through.
        # This is the generalized form of the loop's open-injection-thread
        # nudge, now visible every turn instead of once as a trap right
        # before the final report.
        if discovered and not tested_any_injection:
            actions.append({
                "tool_id": "ghauri",
                "target": target,
                "reason": (
                    f"{len(str(discovered).split(','))} parameter(s) discovered "
                    f"({discovered}) but no injection-class probe has reported "
                    "testing them yet"
                ),
            })

        # Rule 2: HTTP-ish service, parameters never even discovered.
        if (
            not discovered
            and not record.get("arjun_tested")
            and any(record.get(f) for f in _HTTP_HINT_FIELDS)
        ):
            actions.append({
                "tool_id": "arjun",
                "target": target,
                "reason": "HTTP service seen but its parameters were never discovered",
            })

    # Deterministic order: rule-1 (exploitation-readiness) actions first,
    # discovery second; within a rule, sort by target for stability so
    # the render doesn't shuffle between turns.
    actions.sort(key=lambda a: (a["tool_id"] != "ghauri", a["target"]))
    return actions


def render_suggestions(actions: List[Dict[str, str]]) -> str:
    """Compact model-facing render. Empty state is explicit -- an absent
    section would leave the model guessing whether suggestions exist and
    were withheld."""
    if not actions:
        return "(none -- every deterministic follow-up the harness can see has been covered)"
    lines = []
    for i, a in enumerate(actions, 1):
        lines.append(f"{i}. {a['tool_id']} on {a['target']} -- {a['reason']}")
    return "\n".join(lines)
