"""
Prompt assembly, split in two on purpose.

`build_system_prompt` is the STATIC part: rules, target, operator guidance,
seed context, and the tradecraft skills. It is byte-identical across every
turn of a run, so the server's prefix cache holds it -- and everything
after it, the conversation included -- without re-prefilling on each turn.

`build_state_message` is the DYNAMIC part: the engagement log, known facts,
and engagement budget. The loop appends it as the final message of each
API call, after the conversation, and never persists it into the
conversation. Only that tail changes between turns.

Both are rendered in full every turn -- there is no tier that gets a
trimmed version; there is one mode, and the model decides.
"""
from __future__ import annotations

from pathlib import Path

from tradecraft.skills.loader import render_skills

_SYSTEM_PROMPT_PATH = Path(__file__).resolve().parent.parent / "prompts" / "system.md"


def build_system_prompt(
    target: str,
    allowed_tools: list[str] | None = None,
    seed_context: str = "",
    guidance: str = "",
) -> str:
    rules_extra = ""
    if allowed_tools is not None:
        sorted_tools = sorted(allowed_tools)
        rules_extra = (
            f"\n- Active tools for this engagement are restricted by operator policy to: {sorted_tools}. "
            "Any tool mentioned in tradecraft knowledge that is not in this list is UNAVAILABLE and must not be called."
        )
    guidance_block = (
        "\n\n## Operator Guidance\n\n"
        "The operator has given the following guidance for this engagement. "
        "Treat it as priority, not an exclusive boundary -- if you verify a "
        "significant finding outside it in the course of your work, still log "
        f"it via `log_finding`.\n\n{guidance.strip()}"
        if guidance.strip()
        else ""
    )
    seed_block = f"\n\n## Prior Engagement Context\n\n{seed_context}" if seed_context.strip() else ""
    return _SYSTEM_PROMPT_PATH.read_text(encoding="utf-8").format(
        target=target,
        skills=render_skills(),
        rules_extra=rules_extra,
        guidance=guidance_block,
        seed_context=seed_block,
    )


def build_state_message(
    memory_render: str,
    facts_render: str = "(no facts recorded yet)",
    engagement_budget: str = "(not yet computed)",
    coverage_render: str = "",
    suggestions_render: str = "",
    tool_menu_render: str = "",
    verification_render: str = "",
) -> str:
    """The per-turn engagement state, sent as the last message of each API
    call. Not part of the system prompt, and never stored in the
    conversation.

    Optional v2 sections (coverage matrix, deterministic suggestions,
    dynamic tool menu, verification summary) render only when non-empty,
    so callers that haven't adopted them produce byte-identical output
    to the pre-2.0 state message."""
    v2_sections = ""
    if coverage_render:
        v2_sections += (
            "\n\n## Coverage Matrix\n\n"
            "Deterministic tool-reported test coverage per target and class "
            "(VULN=vulnerable, clean=tested-clean, part!=params discovered but "
            "this class untested, -=untested). Gaps here are where the next "
            "tool call usually goes.\n\n"
            f"{coverage_render}"
        )
    if suggestions_render:
        v2_sections += (
            "\n\n## Suggested Next Actions\n\n"
            "Deterministic harness analysis, advisory -- each has a reason; "
            "act on it or dismiss it with your own.\n\n"
            f"{suggestions_render}"
        )
    if verification_render:
        v2_sections += (
            "\n\n## Finding Verification\n\n"
            "Whether each logged finding stands on resolvable evidence. "
            "Use verify_finding to pull the underlying evidence; fix or "
            "retract findings that can't be backed.\n\n"
            f"{verification_render}"
        )
    if tool_menu_render:
        v2_sections += (
            "\n\n## Tool Menu\n\n"
            "Every available tool, one line each. Only tools with LOADED "
            "schemas can be called directly -- activate more with "
            "`load_tool` when you need them.\n\n"
            f"{tool_menu_render}"
        )
    return (
        "[Engagement state, refreshed every turn. This is context from the "
        "harness, not a message from the operator.]\n\n"
        "## Engagement Log So Far\n\n"
        "Your own notes/findings.\n\n"
        f"{memory_render}\n\n"
        "## Known Facts\n\n"
        "What tools have reported so far, deduplicated per port -- not your own "
        "analysis, just the raw record.\n\n"
        f"{facts_render}\n\n"
        "## Engagement Budget\n\n"
        f"{engagement_budget}"
        f"{v2_sections}"
    )
