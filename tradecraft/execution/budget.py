"""
Token budgeting for what goes into each LLM call: HISTORY (the
EngagementMemory log), FACTS (the FactStore table), and CONVERSATION (the
raw tool-call/tool-result transcript), all fit under TOTAL -- the real
backstop, derived from the model's context window minus the output
budget minus a safety margin.

Nothing is pre-capped. HISTORY and FACTS are rendered in full every turn;
trimming only engages on genuine overflow against TOTAL, and then only in
a fixed sacrifice order -- see `render_within_budget`. A flat per-budget
ceiling picked without knowing the real context window either trims
needlessly (when there was room to spare) or not enough (when there
wasn't), so there is no such constant here anymore.

Every trim inserts an explicit elision marker. Nothing is ever silently
dropped.
"""
from __future__ import annotations

import os
from typing import Any, Callable, Dict, List, Tuple

import litellm

DEFAULT_CONVERSATION_TOKEN_BUDGET = int(os.environ.get("TRADECRAFT_CONVERSATION_TOKEN_BUDGET", "0"))
SAFETY_MARGIN_TOKENS = 512  # headroom for template boilerplate/tokenizer estimation error
FALLBACK_CONTEXT_WINDOW = 128_000  # used only when neither LLM_CONTEXT_WINDOW nor litellm knows

TokenCounter = Callable[[str, List[Dict[str, Any]]], int]


def default_token_counter(model: str, messages: List[Dict[str, Any]]) -> int:
    return litellm.token_counter(model=model, messages=messages)


def resolve_context_window(model: str) -> int:
    """Three-tier resolution, in priority order:
    1. LLM_CONTEXT_WINDOW env var, if set -- the operator's own word,
       needed for a self-hosted model litellm has no entry for (confirmed
       for real: litellm.get_model_info raises ModelNotMappedError for
       our own qwen3.8-27b deployment).
    2. litellm's own model database (`litellm.get_model_info`), for a
       known hosted model it does recognize.
    3. FALLBACK_CONTEXT_WINDOW (128k) if neither of the above resolves --
       conservative rather than optimistic, since overestimating risks a
       real context-window overflow at the provider.
    """
    env_value = os.environ.get("LLM_CONTEXT_WINDOW")
    if env_value:
        return int(env_value)

    try:
        info = litellm.get_model_info(model)
    except Exception:
        return FALLBACK_CONTEXT_WINDOW

    window = info.get("max_input_tokens") or info.get("max_tokens")
    return int(window) if window else FALLBACK_CONTEXT_WINDOW


def _count_text(model: str, text: str, counter: TokenCounter) -> int:
    return counter(model, [{"role": "user", "content": text}])


def total_context_budget(context_window: int, max_output_tokens: int) -> int:
    return max(context_window - max_output_tokens - SAFETY_MARGIN_TOKENS, 0)


def trim_history(
    entries: List[Any],
    budget_tokens: int,
    model: str,
    *,
    counter: TokenCounter = default_token_counter,
) -> str:
    """entries: EngagementMemory.entries (newest last). Keeps as many of
    the most recent entries as fit in budget_tokens; drops oldest first.
    `memory.findings()` is untouched by this -- it reads `entries`
    directly, not this rendering."""
    if not entries:
        return "(empty -- nothing logged yet)"

    kept: List[str] = []  # maintained oldest-of-kept-first throughout
    omitted = 0
    for entry in reversed(entries):  # newest first, so we keep the most recent
        line = entry.render()
        candidate = [line, *kept]  # kept is already in correct chronological order
        if _count_text(model, "\n".join(candidate), counter) > budget_tokens and kept:
            omitted = len(entries) - len(kept)
            break
        kept = candidate

    rendered = "\n".join(kept)
    if omitted:
        rendered = f"[{omitted} earlier log entr{'y' if omitted == 1 else 'ies'} omitted to fit the history budget]\n{rendered}"
    return rendered


def trim_facts(
    records: List[Tuple[Any, Dict[str, Any]]],
    budget_tokens: int,
    model: str,
    *,
    counter: TokenCounter = default_token_counter,
) -> str:
    """records: sorted list of ((host, port), record) pairs (FactStore's
    own sort order). Keeps as many as fit; drops oldest-inserted first
    (the end of the list, since FactStore preserves insertion order and
    callers pass it sorted for display -- see note in loop.py)."""
    if not records:
        return "(no facts recorded yet)"

    def render_record(key, record):
        host, port = key
        details = ", ".join(f"{k}={v}" for k, v in record.items() if k not in ("host", "port"))
        return f"{host}:{port} -- {details}" if details else f"{host}:{port}"

    lines = [render_record(k, r) for k, r in records]
    kept: List[str] = []
    omitted = 0
    for line in lines:
        candidate = "\n".join([*kept, line])
        if _count_text(model, candidate, counter) > budget_tokens and kept:
            omitted = len(lines) - len(kept)
            break
        kept.append(line)
    rendered = "\n".join(kept)
    if omitted:
        rendered = f"{rendered}\n[{omitted} more fact{'s' if omitted != 1 else ''} omitted to fit the facts budget]"
    return rendered


def trim_conversation(
    conversation: List[Dict[str, Any]],
    static_tokens: int,
    total_budget: int,
    model: str,
    *,
    counter: TokenCounter = default_token_counter,
    max_conversation_tokens: int = DEFAULT_CONVERSATION_TOKEN_BUDGET,
) -> Tuple[List[Dict[str, Any]], int]:
    """Drops whole oldest turns (one assistant tool_calls message plus
    every tool-result message answering it) from the front until the
    conversation plus static_tokens (system prompt + tools schema, etc.)
    fits total_budget, and also fits max_conversation_tokens if > 0.
    Never splits a tool_calls message from its results -- the API
    requires every tool_call_id to have a matching tool response.
    The very first message (the initial user prompt) is never dropped.
    max_conversation_tokens=0 (default) means elastic: claims whatever
    headroom remains under total_budget.

    Returns (conversation, omitted_turns) -- the caller (render_within_budget,
    and in turn the model-visible prompt) needs the exact count, not just
    the rendered marker text, to report real trimming state factually
    elsewhere. See render_within_budget's own docstring for why."""
    if not conversation:
        return conversation, 0

    def fits(conv: List[Dict[str, Any]]) -> bool:
        conv_tokens = counter(model, conv)
        if static_tokens + conv_tokens > total_budget:
            return False
        if max_conversation_tokens > 0 and conv_tokens > max_conversation_tokens:
            return False
        return True

    if fits(conversation):
        return conversation, 0

    head, rest = conversation[0], list(conversation[1:])
    omitted_turns = 0
    while rest and not fits([head, *rest]):
        # Drop one whole turn: an assistant message, plus every
        # following tool-result message that answers it.
        rest.pop(0)
        omitted_turns += 1
        while rest and rest[0].get("role") == "tool":
            rest.pop(0)

    if omitted_turns == 0:
        return conversation, 0

    marker = {
        "role": "user",
        "content": f"[{omitted_turns} earlier tool-call turn(s) omitted to fit the context window]",
    }
    return [head, marker, *rest], omitted_turns


def render_within_budget(
    history_entries: List[Any],
    facts_records: List[Tuple[Any, Dict[str, Any]]],
    conversation: List[Dict[str, Any]],
    render_system_prompt: Callable[[str, str], str],
    tool_schemas_tokens: int,
    total_budget: int,
    model: str,
    *,
    counter: TokenCounter = default_token_counter,
    max_conversation_tokens: int = DEFAULT_CONVERSATION_TOKEN_BUDGET,
) -> Tuple[str, str, List[Dict[str, Any]], int]:
    """Fits HISTORY, FACTS, and CONVERSATION under total_budget without
    trimming anything that doesn't need it. HISTORY and FACTS are
    rendered in full first; trimming engages only on genuine overflow,
    and then in a fixed sacrifice order:

    1. CONVERSATION first -- by the time a tool result has been
       dispatched, its substance is already captured in FACTS (dense),
       EVIDENCE (full, retrievable via read_evidence/search_evidence),
       and HISTORY (narrative), so the raw transcript is the cheapest
       thing to shrink.
    2. HISTORY next -- free-form prose, lower index value than a fact,
       and `memory.findings()` for the final report reads entries
       directly, so trimming the live render doesn't lose anything from
       the report regardless.
    3. FACTS last, if even that isn't enough -- losing a fact risks the
       model re-scanning a host/port it already covered, and orphans any
       evidence_id pointer that record carried.

    `render_system_prompt(history_render, facts_render)` builds the
    actual system prompt text so real token counts (not pre-guessed
    ceilings) drive every decision here.

    Returns (history_render, facts_render, conversation, conversation_turns_omitted).
    The 4th value is the exact count of whole tool-call turns currently
    missing from `conversation` this turn (0 when nothing was trimmed).
    A stale or ambiguous trim marker left sitting in the conversation
    gives the model no ongoing way to tell whether it still applies or
    how much it means, which risks the model extrapolating an invented,
    ever-growing scarcity from it over later turns. The caller surfaces
    this exact count (never an estimate) in the system prompt instead,
    next to a plain statement of whether there's a turn limit at all --
    directly answering the literal "budget"/"turns" language the model
    used with real numbers rather than leaving it to guess.
    """
    unbounded = float("inf")
    history_render = trim_history(history_entries, unbounded, model, counter=counter)
    facts_render = trim_facts(facts_records, unbounded, model, counter=counter)

    def prompt_tokens(history_r: str, facts_r: str) -> int:
        prompt = render_system_prompt(history_r, facts_r)
        return counter(model, [{"role": "system", "content": prompt}])

    def total_with(history_r: str, facts_r: str, convo: List[Dict[str, Any]]) -> int:
        convo_tokens = counter(model, convo) if convo else 0
        return prompt_tokens(history_r, facts_r) + tool_schemas_tokens + convo_tokens

    # The early return must also respect the explicit CONVERSATION cap: when
    # max_conversation_tokens > 0 the cap is a hard ceiling on its own, even
    # if the total budget still has room (see .env.example's
    # TRADECRAFT_CONVERSATION_TOKEN_BUDGET).
    conversation_within_cap = (
        max_conversation_tokens <= 0
        or not conversation
        or counter(model, conversation) <= max_conversation_tokens
    )
    if conversation_within_cap and total_with(history_render, facts_render, conversation) <= total_budget:
        return history_render, facts_render, conversation, 0

    # Stage 1: shrink CONVERSATION, history/facts still full.
    static_tokens = prompt_tokens(history_render, facts_render) + tool_schemas_tokens
    conversation, omitted_turns = trim_conversation(
        conversation, static_tokens, total_budget, model,
        counter=counter, max_conversation_tokens=max_conversation_tokens,
    )
    if total_with(history_render, facts_render, conversation) <= total_budget:
        return history_render, facts_render, conversation, omitted_turns

    # Stage 2: conversation is already minimal -- shrink HISTORY next.
    conversation_tokens = counter(model, conversation) if conversation else 0
    boilerplate_tokens = prompt_tokens("", "")
    facts_tokens = _count_text(model, facts_render, counter)
    history_ceiling = max(0, total_budget - tool_schemas_tokens - conversation_tokens - boilerplate_tokens - facts_tokens)
    history_render = trim_history(history_entries, history_ceiling, model, counter=counter)
    if total_with(history_render, facts_render, conversation) <= total_budget:
        return history_render, facts_render, conversation, omitted_turns

    # Stage 3: still over even with history minimized -- shrink FACTS
    # last, as a true last resort.
    history_tokens = _count_text(model, history_render, counter)
    facts_ceiling = max(0, total_budget - tool_schemas_tokens - conversation_tokens - boilerplate_tokens - history_tokens)
    facts_render = trim_facts(facts_records, facts_ceiling, model, counter=counter)
    return history_render, facts_render, conversation, omitted_turns

