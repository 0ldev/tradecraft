"""
The execution loop itself: a standard OpenAI-style tool-use loop via
litellm, not a staged pipeline. One continuous conversation; the model
decides what to call and when it's done.

litellm lets Tradecraft point at any local/self-hosted model deployment --
which model answers is plain .env config here, independent of everything
else in this loop.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

import litellm
from litellm.exceptions import (
    APIConnectionError,
    BadGatewayError,
    InternalServerError,
    RateLimitError,
    ServiceUnavailableError,
    Timeout as LiteLLMTimeout,
)

from tradecraft.execution.budget import (
    DEFAULT_CONVERSATION_TOKEN_BUDGET,
    default_token_counter,
    render_within_budget,
    resolve_context_window,
    total_context_budget,
)
from tradecraft.execution.prompts import build_state_message, build_system_prompt
from tradecraft.execution.run_dir import (
    create_initial_manifest,
    finalize_manifest,
    generate_run_id,
    save_facts_json,
    update_latest_symlink,
)
from tradecraft.execution.trace import EngagementTrace, redact_request
from tradecraft.memory.cross_engagement import CrossEngagementMemory
from tradecraft.memory.evidence import EvidenceStore
from tradecraft.memory.facts import FactStore
from tradecraft.memory.log import EngagementMemory
from tradecraft.tools.base import Tool
from tradecraft.tools.evidence_tools import ReadEvidence, SearchEvidence
from tradecraft.tools.memory_tools import LogFinding, LogNote, RecallMemory, RetractFinding
from tradecraft.tools.registry import ALL_TOOLS, openai_tool_schemas

DEFAULT_MODEL = os.environ.get("LLM_MODEL", "")
DEFAULT_BASE_URL = os.environ.get("LLM_BASE_URL") or None
DEFAULT_API_KEY = os.environ.get("LLM_API_KEY") or None
DEFAULT_TIMEOUT = int(os.environ.get("LLM_DECIDER_TIMEOUT", "480"))
DEFAULT_MAX_OUTPUT_TOKENS = int(os.environ.get("LLM_MAX_OUTPUT_TOKENS", "16384"))
# 0 (or any value <= 0) means unlimited -- the model runs until it stops
# calling tools on its own (or a genuine failure ends the engagement).
# There is no "ran out of turns, force a report" fallback in that case,
# since there's no turn count to run out of.
DEFAULT_MAX_TURNS = int(os.environ.get("TRADECRAFT_MAX_TURNS", "0"))

# A reasoning model can spend its whole max_tokens budget on hidden
# reasoning_content before emitting any visible content/tool_call --
# litellm then reports finish_reason="length" with empty content and no
# tool_calls. That is NOT the model deciding it's done; it's a truncated
# response, and treating it as a legitimate stop silently ends an
# engagement with a fake "no report" result. Retry with a larger budget
# before giving up.
MAX_TRUNCATION_RETRIES = 2
TRUNCATION_RETRY_MULTIPLIER = 2
TRUNCATION_RETRY_SYSTEM_NUDGE = (
    "[SYSTEM RETRY NUDGE] Your previous generation was truncated because it exceeded "
    "the output token budget during thinking. Do NOT deliberate or write a long "
    "reasoning monologue. Emit your next tool call or final response immediately."
)

# A larger max_tokens (above) also means a real worst-case generation can
# legitimately take longer -- a request timeout is not a truncation and
# retrying it with a BIGGER token budget would make it worse, not better.
# Retry it as-is, a bounded number of times, instead of letting an
# unhandled litellm exception crash the whole process. A malformed/
# truncated tool-call JSON surfacing as a 500 (InternalServerError)
# because generation cut off mid-string is the same kind of transient
# generation glitch, not a reason to end the engagement. Deliberately excludes
# permanent/non-transient errors (AuthenticationError, BadRequestError,
# ContentPolicyViolationError, ContextWindowExceededError, ...) where
# retrying identically can't help.
MAX_NETWORK_RETRIES = 2
_RETRYABLE_NETWORK_ERRORS = (
    LiteLLMTimeout,
    APIConnectionError,
    ServiceUnavailableError,
    RateLimitError,
    InternalServerError,
    BadGatewayError,
)


@dataclass
class EngagementResult:
    report: str
    findings: List[str] = field(default_factory=list)
    transcript: List[Dict[str, Any]] = field(default_factory=list)
    turns_used: int = 0
    stats: Dict[str, Any] = field(default_factory=dict)
    facts: FactStore = field(default_factory=FactStore)
    evidence: EvidenceStore = field(default_factory=EvidenceStore)
    run_id: str | None = None
    run_dir: Path | None = None
    target: str | None = None


def _build_tool_map(
    memory: EngagementMemory,
    tool_ids: List[str] | None = None,
    evidence: EvidenceStore | None = None,
    allow_destructive: bool = False,
    allow_destructive_categories: frozenset[str] = frozenset(),
    credential_budget: int | None = None,
    cross_memory: CrossEngagementMemory | None = None,
    current_run_id: str | None = None,
) -> Dict[str, Tool]:
    """tool_ids=None (default) makes every registered tool available, same
    as before this existed. An explicit list restricts the engagement to
    just those tool_ids -- log_note/log_finding/retract_finding/recall_memory and
    read_evidence/search_evidence are always included regardless, since they're
    how the model records and retrieves things, not an attack/recon capability
    to opt in or out of.

    A tool whose own is_available() returns False (missing binary,
    missing/invalid credential -- whatever that tool's own override
    checks) is dropped here, before its schema is ever built. This
    compensates for a concrete, recurring tool risk: offering a tool
    the model can never actually use wastes both context (one more
    schema rendered every turn for nothing) and a turn (the model
    calls it, learns it can't work, and has to recover) -- it doesn't
    second-guess any tool the model COULD actually run. Tool.__call__'s
    own is_available() check is unchanged and stays as defense-in-depth
    for whatever's left (e.g. a binary removed mid-run)."""
    available: Dict[str, Tool] = {t.spec.name: t for t in ALL_TOOLS}
    if tool_ids is None:
        tools = dict(available)
    else:
        unknown = sorted(set(tool_ids) - set(available))
        if unknown:
            raise ValueError(
                f"unknown tool(s) {unknown} -- available: {sorted(available)}"
            )
        tools = {name: available[name] for name in tool_ids}

    unavailable = sorted(name for name, t in tools.items() if not t.is_available())
    if unavailable:
        # Printed directly rather than through the on_event/emit path:
        # this runs before run_engagement's `emit` closure exists, and
        # changing this function's return shape to carry the excluded
        # list back out would break _build_tool_map's existing direct
        # callers in tests/test_tool_selection.py and
        # tests/test_gowitness_tool.py, which is a disproportionate
        # blast radius for a startup diagnostic.
        print(
            f"[tradecraft] excluded {len(unavailable)} unavailable tool(s) from this "
            f"engagement (missing binary or credential): {unavailable}"
        )
        tools = {name: t for name, t in tools.items() if name not in unavailable}

    from tradecraft.policy.destructive import is_allowed
    blocked_destructive = sorted(
        name for name, t in tools.items()
        if t.is_available() and not is_allowed(
            t.destructive_categories, allow_destructive, allow_destructive_categories
        )
    )
    if blocked_destructive:
        print(
            f"[tradecraft] excluded {len(blocked_destructive)} destructive tool(s) from this "
            f"engagement (--allow-destructive/--allow-destructive-categories insufficient): {blocked_destructive}"
        )
        tools = {name: t for name, t in tools.items() if name not in blocked_destructive}

    store = evidence if evidence is not None else EvidenceStore()
    for memory_tool in (
        LogNote(memory),
        LogFinding(memory, evidence=store),
        RetractFinding(memory),
        RecallMemory(store=cross_memory, current_run_id=current_run_id),
    ):
        tools[memory_tool.spec.name] = memory_tool
    for ev_tool in (ReadEvidence(store), SearchEvidence(store)):
        tools[ev_tool.spec.name] = ev_tool
    if "gowitness" in tools:
        from tradecraft.tools.gowitness import Gowitness
        tools["gowitness"] = Gowitness(store)
    if "hydra" in tools or "kerbrute_spray" in tools:
        from tradecraft.policy.credential_budget import TOTAL_BUDGET_PER_ENDPOINT, CredentialLedger
        credential_ledger = CredentialLedger(
            total_budget=credential_budget if credential_budget is not None else TOTAL_BUDGET_PER_ENDPOINT
        )
        if "hydra" in tools:
            from tradecraft.tools.hydra import Hydra
            tools["hydra"] = Hydra(credential_ledger)
        if "kerbrute_spray" in tools:
            from tradecraft.tools.kerbrute_spray import KerbruteSpray
            tools["kerbrute_spray"] = KerbruteSpray(credential_ledger)
    return tools


def _is_truncated_empty(response: Any) -> bool:
    """True when the model ran out of output tokens (finish_reason ==
    "length") without producing any visible content or a tool call --
    reasoning_content ate the whole budget. Never a legitimate stop."""
    choice = response.choices[0]
    message = choice.message
    tool_calls = getattr(message, "tool_calls", None)
    content = (message.content or "").strip()
    return choice.finish_reason == "length" and not tool_calls and not content


def _has_truncated_tool_calls(response: Any) -> bool:
    """True when finish_reason == 'length' and any generated tool call has
    unparseable/truncated JSON arguments due to token exhaustion mid-string."""
    if not response or not getattr(response, "choices", None):
        return False
    choice = response.choices[0]
    if choice.finish_reason != "length":
        return False
    message = choice.message
    tool_calls = getattr(message, "tool_calls", None)
    if not tool_calls:
        return False
    for tc in tool_calls:
        fn = getattr(tc, "function", None)
        args = getattr(fn, "arguments", "") if fn else ""
        try:
            json.loads(args or "{}")
        except (json.JSONDecodeError, TypeError, ValueError):
            return True
    return False


def _is_truncated_response(response: Any) -> bool:
    """True when the response was truncated due to output token limit
    (finish_reason == 'length') either with no visible output or with
    truncated/unparseable tool call arguments."""
    return _is_truncated_empty(response) or _has_truncated_tool_calls(response)


def _is_tool_call_truncation_error(exc: Exception) -> bool:
    """True when an exception indicates that the server failed to parse the model's
    tool call arguments as JSON due to output token exhaustion mid-generation."""
    msg = str(exc).lower()
    return (
        "failed to parse tool call" in msg
        or ("tool call" in msg and "json" in msg and "parse" in msg)
        or ("syntax error while parsing" in msg)
        or "json.exception.parse_error" in msg
        or "unexpected end of input" in msg
        or "missing closing quote" in msg
    )


def _has_open_injection_thread(facts: FactStore) -> bool:
    """True if some (host, port) record shows parameters discovered
    (arjun_params_discovered or params_discovered) with none of the
    three injection-class tested fields (sqli_tested, sqli_injectable,
    xss_tested, cmdi_tested) present on that same record. Host:port-
    granular: a false negative here (missed due to a scheme/port
    mismatch between the discovery and testing calls) just means the
    nudge doesn't fire on that edge case, never a false block on
    anything the model could otherwise do."""
    tested_fields = (
        "sqli_tested",
        "sqli_injectable",
        "xss_tested",
        "cmdi_tested",
        "open_redirect_tested",
        "open_redirect_vulnerable",
        "ssrf_tested",
        "ssrf_vulnerable",
        "nosql_tested",
        "nosql_vulnerable",
        "crlf_tested",
        "crlf_vulnerable",
        "arjun_tested",
    )
    for _, record in facts.sorted_records():
        discovered = record.get("arjun_params_discovered") or record.get("params_discovered")
        if discovered and not any(record.get(f) for f in tested_fields):
            return True
    return False


def _has_open_interactsh_thread(conversation: List[Dict[str, Any]]) -> bool:
    """True if the most recent interactsh 'generate' call in this
    conversation has no 'poll' call after it -- an OOB payload was
    created (e.g. for a blind-SSRF/SQLi/command-injection check) and
    never checked for a callback before the model tried to finalize.
    Same shape as _has_open_injection_thread -- a one-turn nudge the
    model can still decline with a reason, never a block."""
    last_generate_idx = None
    last_poll_idx = None
    for idx, msg in enumerate(conversation):
        if msg.get("role") != "assistant":
            continue
        for tc in (msg.get("tool_calls") or []):
            fn = tc.get("function") or {}
            if fn.get("name") != "interactsh":
                continue
            try:
                action = json.loads(fn.get("arguments") or "{}").get("action")
            except (ValueError, TypeError):
                continue
            if action == "generate":
                last_generate_idx = idx
            elif action == "poll":
                last_poll_idx = idx
    if last_generate_idx is None:
        return False
    return last_poll_idx is None or last_poll_idx < last_generate_idx


def _engagement_budget_text(turn: int, max_turns: int, conversation_turns_omitted: int) -> str:
    """Exact numbers, never an estimate, for the two concrete things the
    model actually needs to know: is there a turn limit, and has
    trimming actually happened. A model given "turn budget"/"remaining
    budget" language with no real number behind it, or a stale
    retrospective trim marker with no ongoing way to tell whether it
    still applies, risks extrapolating an invented, ever-growing
    scarcity on its own. Answer both literal questions directly instead."""
    if max_turns <= 0:
        turn_status = (
            "No turn limit for this engagement -- investigate as thoroughly "
            "as the target's attack surface warrants."
        )
    else:
        turn_status = f"Turn {turn} of {max_turns} ({max_turns - turn} remaining)."

    if conversation_turns_omitted > 0:
        trim_status = (
            f" {conversation_turns_omitted} earlier tool-call turn(s) are currently trimmed "
            "from the conversation below. This is automatic and lossless -- their substance "
            "is already captured in Known Facts, the Engagement Log, and Evidence -- never a "
            "reason to narrow investigation scope."
        )
    else:
        trim_status = " No conversation trimming has happened yet."

    return turn_status + trim_status


def _complete_with_retry(
    *,
    model: str,
    base_url: str | None,
    api_key: str | None,
    messages: List[Dict[str, Any]],
    timeout: int,
    max_tokens: int,
    tools: List[Dict[str, Any]] | None = None,
    trace: EngagementTrace,
    turn: int,
    call_kind: str,
    token_breakdown: Dict[str, int] | None = None,
    emit=lambda kind, payload: None,
) -> Any:
    attempt_tokens = max_tokens
    response = None
    reasoning_effort = os.environ.get("LLM_REASONING_EFFORT")
    for attempt in range(MAX_TRUNCATION_RETRIES + 1):
        attempt_messages = list(messages)
        if attempt > 0:
            attempt_messages.append({
                "role": "user",
                "content": TRUNCATION_RETRY_SYSTEM_NUDGE,
            })
        kwargs: Dict[str, Any] = dict(
            model=model, api_base=base_url, api_key=api_key,
            messages=attempt_messages, timeout=timeout, max_tokens=attempt_tokens,
        )
        if reasoning_effort:
            kwargs["reasoning_effort"] = "low" if attempt > 0 else reasoning_effort
        if attempt > 0:
            extra_body = kwargs.setdefault("extra_body", {})
            chat_template_kwargs = extra_body.setdefault("chat_template_kwargs", {})
            chat_template_kwargs["enable_thinking"] = False
        if tools:
            kwargs["tools"] = tools
        try:
            response = _complete_with_network_retry(
                kwargs, trace=trace, turn=turn, call_kind=call_kind, truncation_attempt=attempt,
                token_breakdown=token_breakdown, emit=emit,
            )
        except Exception as exc:
            if _is_tool_call_truncation_error(exc) and attempt < MAX_TRUNCATION_RETRIES:
                attempt_tokens *= TRUNCATION_RETRY_MULTIPLIER
                emit("truncation_retry", {
                    "attempt": attempt + 1,
                    "next_max_tokens": attempt_tokens,
                    "error": f"{type(exc).__name__}: {exc}",
                })
                continue
            raise

        if not _is_truncated_response(response):
            return response
        if attempt < MAX_TRUNCATION_RETRIES:
            attempt_tokens *= TRUNCATION_RETRY_MULTIPLIER
            emit("truncation_retry", {"attempt": attempt + 1, "next_max_tokens": attempt_tokens})
    return response


def _complete_with_network_retry(
    kwargs: Dict[str, Any],
    *,
    trace: EngagementTrace,
    turn: int,
    call_kind: str,
    truncation_attempt: int,
    token_breakdown: Dict[str, int] | None = None,
    emit=lambda kind, payload: None,
) -> Any:
    last_exc: Exception | None = None
    for attempt in range(MAX_NETWORK_RETRIES + 1):
        try:
            with trace.call(
                turn=turn, call_kind=call_kind, truncation_attempt=truncation_attempt,
                network_attempt=attempt, request=redact_request(kwargs), token_breakdown=token_breakdown,
            ) as handle:
                response = litellm.completion(**kwargs)
                handle.set_response(response)
                return response
        except _RETRYABLE_NETWORK_ERRORS as exc:
            last_exc = exc
            emit("network_retry", {"attempt": attempt + 1, "error": f"{type(exc).__name__}: {exc}"})
    raise last_exc


def run_engagement(
    target: str,
    *,
    model: str = DEFAULT_MODEL,
    base_url: str | None = DEFAULT_BASE_URL,
    api_key: str | None = DEFAULT_API_KEY,
    timeout: int = DEFAULT_TIMEOUT,
    max_output_tokens: int = DEFAULT_MAX_OUTPUT_TOKENS,
    max_turns: int = DEFAULT_MAX_TURNS,
    persist_log_path: str | None = None,
    persist_trace_path: str | None = None,
    persist_evidence_dir: str | None = None,
    run_dir: str | Path | None = None,
    run_id: str | None = None,
    mode: str = "fresh",
    seed_from: str | None = None,
    seed_context: str = "",
    guidance: str = "",
    tool_ids: List[str] | None = None,
    allow_destructive: bool = False,
    allow_destructive_categories: frozenset[str] = frozenset(),
    credential_budget: int | None = None,
    profile: str | None = None,
    conversation_token_budget: int = DEFAULT_CONVERSATION_TOKEN_BUDGET,
    on_event=None,
) -> EngagementResult:
    """Run one engagement loop to completion and return the final report.

    `on_event(kind, payload)` is called for each tool call/result and
    model text block, if given -- for live CLI output. Entirely optional;
    the loop works the same without it.

    `tool_ids`, if given, restricts the engagement to that subset of
    registered tools (see `_build_tool_map`); `None` (default) keeps
    every registered tool available, same as before this existed.

    `profile` is recorded into manifest.json only (the CLI has already
    resolved --profile/--tools down to `tool_ids` by the time it calls
    this function) -- it exists so a run directory on disk can say which
    named profile produced this engagement's tool_ids, instead of only
    the resolved id list with no way to tell it came from a profile
    versus an explicit --tools list.

    `guidance` is free-text operator instruction/observation/focus for this
    engagement -- rendered into the static system prompt as advisory
    priority, never an enforced constraint (see `docs/cli.md`).
    """
    if not model:
        raise ValueError(
            "no model configured -- set LLM_MODEL (and LLM_BASE_URL) in .env; "
            "see .env.example"
        )

    run_dir_path = Path(run_dir) if run_dir else None
    run_id_val = run_id or (run_dir_path.name if run_dir_path else generate_run_id())
    if run_dir_path:
        create_initial_manifest(
            run_dir=run_dir_path,
            run_id=run_id_val,
            target=target,
            model=model,
            max_turns=max_turns,
            mode=mode,
            seed_from=seed_from,
            guidance=guidance or None,
            profile=profile,
            tool_ids=tool_ids,
            allow_destructive=allow_destructive,
            allow_destructive_categories=allow_destructive_categories,
            credential_budget=credential_budget,
        )

    # Resolve cross-engagement memory store. When run_dir_path is under a
    # `<tradecraft_home>/targets/<target>/runs/<run_id>` hierarchy, co-locate
    # memory.db under that same `<tradecraft_home>` so isolated test homes stay
    # isolated; otherwise use default `$TRADECRAFT_HOME/memory.db`.
    inferred_home: Path | None = None
    if run_dir_path and run_dir_path.parent.name == "runs" and run_dir_path.parent.parent.parent.name == "targets":
        inferred_home = run_dir_path.parent.parent.parent.parent
    cross_memory = (
        CrossEngagementMemory(tradecraft_home=inferred_home)
        if run_dir_path is not None
        else CrossEngagementMemory(db_path=":memory:")
    )

    # Turn-0 static root-domain seeding: if no explicit --seed-from
    # context was passed, check if prior runs exist for this target or its
    # registrable root domain (e.g. sibling subdomains) and populate seed_context
    # once before Turn 1 so the system prompt remains 100% static across turns.
    effective_seed_context = seed_context
    if not effective_seed_context.strip():
        try:
            auto_seed = cross_memory.build_target_seed_context(
                target, exclude_run_id=run_id_val
            )
            if auto_seed:
                effective_seed_context = auto_seed
        except Exception:
            pass

    memory = EngagementMemory(persist_path=persist_log_path)
    trace = EngagementTrace(persist_path=persist_trace_path)
    evidence = EvidenceStore(persist_dir=persist_evidence_dir)
    facts = FactStore()
    tool_map = _build_tool_map(
        memory,
        tool_ids,
        evidence=evidence,
        allow_destructive=allow_destructive,
        allow_destructive_categories=allow_destructive_categories,
        credential_budget=credential_budget,
        cross_memory=cross_memory,
        current_run_id=run_id_val,
    )
    tool_schemas = openai_tool_schemas(tool_map.values())

    conversation: List[Dict[str, Any]] = [
        {"role": "user", "content": f"Begin the engagement against: {target}"}
    ]

    total_budget = total_context_budget(resolve_context_window(model), max_output_tokens)

    def emit(kind: str, payload: Any) -> None:
        if on_event:
            on_event(kind, payload)

    def _finish_run(clean_completion: bool = True) -> None:
        if run_dir_path:
            save_facts_json(run_dir_path, facts)
            finalize_manifest(
                run_dir=run_dir_path,
                turns_used=turns_used,
                findings_count=len(memory.findings()),
            )
            if clean_completion and run_dir_path.parent.name == "runs":
                update_latest_symlink(run_dir_path.parent.parent, run_id_val)
            try:
                cross_memory.index_live_run(
                    run_id=run_id_val,
                    target=target,
                    memory=memory,
                    facts=facts,
                )
            except Exception:
                pass

    def build_prompt_and_messages() -> tuple[str, List[Dict[str, Any]], Dict[str, int]]:
        tool_schemas_json = json.dumps(tool_schemas)
        tool_schemas_tokens = default_token_counter(model, [{"role": "user", "content": tool_schemas_json}])
        # render_within_budget sizes HISTORY and FACTS against the whole
        # non-conversation prompt. The callback therefore returns the system
        # text plus the state message, so both are counted. The trim-count
        # line inside the state message is sized with 0 omitted turns here,
        # because the real count is only known after trimming. Its
        # length varies by a few tokens, which the context margin covers.
        history_render, facts_render, trimmed_conversation, conversation_turns_omitted = render_within_budget(
            memory.entries,
            facts.sorted_records(),
            conversation,
            lambda history_r, facts_r: (
                build_system_prompt(target, allowed_tools=list(tool_map.keys()), seed_context=effective_seed_context, guidance=guidance)
                + build_state_message(
                    history_r, facts_r, _engagement_budget_text(turn, max_turns, 0),
                )
            ),
            tool_schemas_tokens,
            total_budget,
            model,
            counter=default_token_counter,
            max_conversation_tokens=conversation_token_budget,
        )
        # Static system message: identical on every turn, so it stays
        # cacheable. Dynamic state goes last, after the conversation.
        system_prompt = build_system_prompt(target, allowed_tools=list(tool_map.keys()), seed_context=effective_seed_context, guidance=guidance)
        state_message = build_state_message(
            history_render,
            facts_render,
            _engagement_budget_text(turn, max_turns, conversation_turns_omitted),
        )
        # Component counts for the trace. The additive total to sanity-check
        # against the API's own usage["prompt_tokens"] is
        # system_prompt_total + state_message + conversation + tool_schemas.
        system_prompt_total = default_token_counter(model, [{"role": "system", "content": system_prompt}])
        state_message_total = default_token_counter(model, [{"role": "user", "content": state_message}])
        token_breakdown = {
            "facts": default_token_counter(model, [{"role": "user", "content": facts_render}]),
            "history": default_token_counter(model, [{"role": "user", "content": history_render}]),
            "system_prompt_total": system_prompt_total,
            "state_message": state_message_total,
            "tool_schemas": tool_schemas_tokens,
            "conversation": default_token_counter(model, trimmed_conversation) if trimmed_conversation else 0,
        }
        token_breakdown["estimated_prompt_total"] = (
            token_breakdown["system_prompt_total"]
            + token_breakdown["state_message"]
            + token_breakdown["conversation"]
        )
        # NOTE: tool_schemas tokens are deliberately excluded from the
        # total above -- whether a given API call actually sends `tools=`
        # depends on the call site (the turn loop does, the forced
        # final-report call doesn't), not on anything this function
        # knows. Each call site adds tool_schemas into its own copy of
        # the total only when it actually passes `tools=` below.
        messages = [
            {"role": "system", "content": system_prompt},
            *trimmed_conversation,
            {"role": "user", "content": state_message},
        ]
        return system_prompt, messages, token_breakdown

    already_nudged_before_final_report = False
    already_nudged_interactsh = False
    turns_used = 0
    turn = 0
    # max_turns <= 0 means unlimited: keep looping until the model stops
    # calling tools on its own or a failure ends the engagement. When
    # max_turns > 0, this runs exactly max_turns times, then falls
    # through to the forced-final-report path below.
    while max_turns <= 0 or turn < max_turns:
        turn += 1
        turns_used = turn
        system_prompt, messages, token_breakdown = build_prompt_and_messages()
        # This call does pass tools=tool_schemas below -- unlike the
        # forced final-report call -- so its estimate must include them.
        token_breakdown["estimated_prompt_total"] += token_breakdown["tool_schemas"]

        try:
            response = _complete_with_retry(
                model=model, base_url=base_url, api_key=api_key,
                messages=messages, tools=tool_schemas,
                timeout=timeout, max_tokens=max_output_tokens,
                trace=trace, turn=turn, call_kind="turn", token_breakdown=token_breakdown, emit=emit,
            )
        except _RETRYABLE_NETWORK_ERRORS as exc:
            # Exhausted network retries -- end the engagement with an
            # honest result, not an unhandled crash. Same reasoning as
            # the truncation case: a transient infra failure is not the
            # model deciding it's done, so it must read as a failure,
            # not a calm final report.
            _finish_run(clean_completion=False)
            return EngagementResult(
                report=(
                    f"(engagement ended early: persistent network error talking to the "
                    f"model after {MAX_NETWORK_RETRIES} retries -- {type(exc).__name__}: {exc})"
                ),
                findings=memory.findings(),
                transcript=conversation,
                turns_used=turns_used,
                stats=trace.summary(),
                facts=facts,
                evidence=evidence,
                run_id=run_id_val,
                run_dir=run_dir_path,
                target=target,
            )
        message = response.choices[0].message

        if message.content and message.content.strip():
            emit("text", message.content)

        tool_calls = getattr(message, "tool_calls", None)
        if not tool_calls:
            if _is_truncated_empty(response):
                # Ran out of retries and still got nothing visible --
                # an execution failure, not the model deciding it's
                # done. Say so plainly rather than returning a report
                # that looks like a deliberate, calm stop.
                report_text = (
                    f"(engagement ended early: the model's response was truncated "
                    f"(finish_reason=length) with no visible output after "
                    f"{MAX_TRUNCATION_RETRIES} retries -- not a deliberate stop)"
                )
                _finish_run(clean_completion=True)
                return EngagementResult(
                    report=report_text,
                    findings=memory.findings(),
                    transcript=conversation,
                    turns_used=turns_used,
                    stats=trace.summary(),
                    facts=facts,
                    evidence=evidence,
                    run_id=run_id_val,
                    run_dir=run_dir_path,
                    target=target,
                )

            # Only nudge if another turn is actually available -- never
            # on the last allowed turn, where there'd be nothing left to
            # spend it on anyway.
            turn_available = max_turns <= 0 or turn < max_turns
            # Only nudge if there's something structurally open to
            # check -- never unconditionally.
            if (
                not already_nudged_before_final_report
                and turn_available
                and _has_open_injection_thread(facts)
            ):
                already_nudged_before_final_report = True
                conversation.append({"role": "assistant", "content": message.content or ""})
                conversation.append({
                    "role": "user",
                    "content": (
                        "Before finalizing: FACTS shows at least one host:port "
                        "with discovered parameters (arjun_params_discovered or "
                        "params_discovered) that no parameter probe or injection tool has reported "
                        "testing yet (no sqli_tested, sqli_injectable, xss_tested, "
                        "cmdi_tested, open_redirect_tested, or ssrf_tested on that same record). If something cheap "
                        "is still worth checking there, do it now. Otherwise, say "
                        "explicitly why it's not worth pursuing (e.g. the "
                        "endpoint is static, auth-gated, or already covered under "
                        "a different host:port), then write your final report."
                    ),
                })
                continue  # one more turn, tools still available, same budget

            if (
                not already_nudged_interactsh
                and turn_available
                and _has_open_interactsh_thread(conversation)
            ):
                already_nudged_interactsh = True
                conversation.append({"role": "assistant", "content": message.content or ""})
                conversation.append({
                    "role": "user",
                    "content": (
                        "Before finalizing: the most recent interactsh payload "
                        "generated in this engagement has no 'poll' call after it, "
                        "so it's unknown whether it ever received a callback. If "
                        "it's still worth checking, poll for it now. Otherwise, say "
                        "explicitly why it's not worth checking (e.g. the request "
                        "meant to use it was never actually sent), then write your "
                        "final report."
                    ),
                })
                continue  # one more turn, tools still available, same budget

            # Nothing open, already nudged, or no turn left to spend --
            # this is final.
            report_text = message.content or "(model produced no final report text)"
            _finish_run(clean_completion=True)
            return EngagementResult(
                report=report_text,
                findings=memory.findings(),
                transcript=conversation,
                turns_used=turns_used,
                stats=trace.summary(),
                facts=facts,
                evidence=evidence,
                run_id=run_id_val,
                run_dir=run_dir_path,
                target=target,
            )

        conversation.append(
            {
                "role": "assistant",
                "content": message.content,
                "tool_calls": [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {"name": tc.function.name, "arguments": tc.function.arguments},
                    }
                    for tc in tool_calls
                ],
            }
        )

        for tc in tool_calls:
            try:
                params = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError as exc:
                result = {"error": f"malformed tool arguments: {exc}"}
            else:
                result = _dispatch_tool(tc.function.name, params, tool_map, facts, evidence=evidence)
            emit("tool_result", {"name": tc.function.name, "input": params if isinstance(params, dict) else {}, "result": result})
            conversation.append(
                {"role": "tool", "tool_call_id": tc.id, "content": json.dumps(result, default=str)}
            )

        if run_dir_path:
            save_facts_json(run_dir_path, facts)

    # Hit the turn budget without the model wrapping up on its own --
    # force a final report rather than silently truncating.
    conversation.append(
        {
            "role": "user",
            "content": (
                "You've reached the turn budget for this engagement. Stop "
                "calling tools now and write your final report based on "
                "everything logged so far."
            ),
        }
    )
    _, final_messages, final_token_breakdown = build_prompt_and_messages()
    try:
        final = _complete_with_retry(
            model=model, base_url=base_url, api_key=api_key,
            messages=final_messages,
            timeout=timeout, max_tokens=max_output_tokens,
            trace=trace, turn=turns_used, call_kind="final_report", token_breakdown=final_token_breakdown, emit=emit,
        )
        report_text = final.choices[0].message.content or "(no report produced)"
    except _RETRYABLE_NETWORK_ERRORS as exc:
        report_text = (
            f"(engagement ended early: persistent network error talking to the "
            f"model after {MAX_NETWORK_RETRIES} retries -- {type(exc).__name__}: {exc})"
        )
    _finish_run(clean_completion=True)
    return EngagementResult(
        report=report_text,
        findings=memory.findings(),
        transcript=conversation,
        turns_used=turns_used,
        stats=trace.summary(),
        facts=facts,
        evidence=evidence,
        run_id=run_id_val,
        run_dir=run_dir_path,
        target=target,
    )


def _dispatch_tool(
    name: str,
    params: Dict[str, Any],
    tool_map: Dict[str, Tool],
    facts: FactStore,
    evidence: EvidenceStore | None = None,
) -> Dict[str, Any]:
    tool = tool_map.get(name)
    if tool is None:
        from tradecraft.tools.registry import ALL_TOOLS
        registered_by_name = {t.spec.name: t for t in ALL_TOOLS}
        if name in registered_by_name:
            allowed = sorted(tool_map.keys())
            matched_tool = registered_by_name[name]
            if matched_tool.destructive:
                return {
                    "error": (
                        f"tool '{name}' is destructive and --allow-destructive was not "
                        f"set for this engagement -- available tools: {allowed}"
                    )
                }
            return {
                "error": (
                    f"tool '{name}' is disabled for this engagement by operator policy -- "
                    f"available tools: {allowed}"
                )
            }
        return {"error": f"unknown tool '{name}'"}

    # Each tool declares its own scope_param (from config/tools/<id>.yaml) --
    # the name of the parameter that carries its network target. There is
    # no scope-file enforcement against it (removed; see docs/policy.md
    # for where gating policy lives now); this is just a basic presence
    # check so a tool can't silently run with its target parameter missing.
    target_param = tool.scope_param
    if target_param and not params.get(target_param):
        return {"error": f"missing required parameter '{target_param}'"}

    result = tool(**params)

    # Offload detailed evidence to the run's EvidenceStore if supported
    if evidence is not None:
        try:
            ev = tool.extract_evidence(params, result)
            if ev is not None:
                if len(ev) == 3:
                    ev_target, ev_data, ev_aliases = ev
                else:
                    ev_target, ev_data = ev
                    ev_aliases = None
                evidence_id = evidence.save(ev_target, tool.tool_id, ev_data, aliases=ev_aliases)
                result["evidence_id"] = evidence_id
        except Exception as exc:
            # Fall back safely without crashing the engagement.
            result["evidence_write_error"] = str(exc)

    # Merge whatever deterministic (host, port) facts this result reports
    # into the shared FactStore -- never model-asserted, see
    # tradecraft/memory/facts.py. A tool with nothing to report (error, or a
    # tool with no extract_facts override) contributes nothing. Runs after
    # extract_evidence (above) so a batch tool's extract_facts can still
    # see the untruncated `_full_evidence` data if its own extract_evidence
    # peeked at it rather than popping it -- producing a fact for every
    # target in the batch, not just the subset kept in the model-facing
    # result for display. Whether or not that happened, `_full_evidence`
    # is stripped below so it never reaches the model either way.
    facts.merge_many(tool.extract_facts(params, result))
    result.pop("_full_evidence", None)
    return result
