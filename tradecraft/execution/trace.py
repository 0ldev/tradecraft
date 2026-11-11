"""
Full observability record of every real LLM call an engagement makes --
exact request payload, response (content/reasoning_content/tool_calls),
finish_reason, token usage, and wall-clock duration for each one.
Operator-facing only: nothing recorded here ever feeds back into the
prompt the model sees (contrast with tradecraft/memory/log.py, which is
model-facing by design and deliberately dumb/compact). This exists
because, before it, debugging a slow/expensive/wrong-decision run meant
hand-writing a one-off script to dump the payload -- see the truncation
and network-retry investigations that led to this module.

One call to litellm.completion() (successful, truncated, or raising) is
one record -- including every truncation-retry and network-retry
attempt, not just the turn-level outcome, so "how many calls did this
really make" is answerable from the trace alone.
"""
from __future__ import annotations

import json
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional


def _usage_to_dict(usage: Any) -> Optional[Dict[str, Any]]:
    if usage is None:
        return None
    if hasattr(usage, "model_dump"):
        return usage.model_dump()
    if hasattr(usage, "__dict__"):
        return {k: v for k, v in vars(usage).items() if not k.startswith("_")}
    return None


@dataclass
class CallRecord:
    index: int
    turn: int
    call_kind: str  # "turn" | "final_report"
    truncation_attempt: int
    network_attempt: int
    request: Dict[str, Any]
    duration_seconds: float
    timestamp: str  # wall-clock UTC ISO8601, set when the call starts
    content: Optional[str] = None
    reasoning_content: Optional[str] = None
    tool_call_names: List[str] = field(default_factory=list)
    tool_calls: List[Dict[str, Any]] = field(default_factory=list)
    finish_reason: Optional[str] = None
    usage: Optional[Dict[str, Any]] = None
    # Our own component token counts at prompt-build time (system_prompt
    # already includes facts/history/skills baked in via the template --
    # it is NOT additive with the "facts"/"history" entries, those are
    # reported separately only so facts/history growth is visible on
    # their own). The additive, non-overlapping total to compare against
    # `usage["prompt_tokens"]` (the real backend-reported count) is
    # system_prompt_total + state_message + tool_schemas + conversation -- see
    # `estimated_prompt_total`. A real, growing gap between that estimate
    # and usage["prompt_tokens"] means the budgeting math is wrong, not
    # just normal tokenizer-estimation slack.
    token_breakdown: Optional[Dict[str, int]] = None
    error: Optional[str] = None

    def to_json(self) -> str:
        return json.dumps(vars(self), default=str)


class EngagementTrace:
    """Optionally persisted to a JSONL file (one call per line) via
    `persist_path`; always kept in memory for `summary()` regardless."""

    def __init__(self, persist_path: str | None = None):
        self.calls: List[CallRecord] = []
        self.persist_path = Path(persist_path) if persist_path else None
        if self.persist_path:
            self.persist_path.write_text("")  # fresh file for this run

    @contextmanager
    def call(
        self, *, turn: int, call_kind: str, truncation_attempt: int, network_attempt: int, request: Dict[str, Any],
        token_breakdown: Optional[Dict[str, int]] = None,
    ) -> Iterator["_CallHandle"]:
        """Times one litellm.completion() attempt and records it on exit,
        whether it succeeded, got a truncated-empty response, or raised.
        `request` should already have any secret (api_key) redacted.
        `token_breakdown`, if given, is this call's component token
        counts computed at prompt-build time -- see `CallRecord`."""
        handle = _CallHandle()
        start = time.monotonic()
        timestamp = datetime.now(timezone.utc).isoformat()
        try:
            yield handle
        except Exception as exc:
            self._append(
                turn=turn, call_kind=call_kind, truncation_attempt=truncation_attempt,
                network_attempt=network_attempt, request=request, timestamp=timestamp,
                duration_seconds=time.monotonic() - start, token_breakdown=token_breakdown,
                error=f"{type(exc).__name__}: {exc}",
            )
            raise
        else:
            message = None
            finish_reason = None
            usage = None
            if handle.response is not None:
                choice = handle.response.choices[0]
                message = choice.message
                finish_reason = choice.finish_reason
                usage = getattr(handle.response, "usage", None)
            raw_tool_calls = (getattr(message, "tool_calls", None) or []) if message else []
            self._append(
                turn=turn, call_kind=call_kind, truncation_attempt=truncation_attempt,
                network_attempt=network_attempt, request=request, timestamp=timestamp,
                duration_seconds=time.monotonic() - start, token_breakdown=token_breakdown,
                content=getattr(message, "content", None) if message else None,
                reasoning_content=getattr(message, "reasoning_content", None) if message else None,
                tool_call_names=[tc.function.name for tc in raw_tool_calls],
                tool_calls=[
                    {
                        "id": getattr(tc, "id", None),
                        "type": getattr(tc, "type", "function") or "function",
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments,
                        },
                    }
                    for tc in raw_tool_calls
                ],
                finish_reason=finish_reason,
                usage=_usage_to_dict(usage),
            )

    def _append(self, **kwargs: Any) -> None:
        record = CallRecord(index=len(self.calls) + 1, **kwargs)
        self.calls.append(record)
        if self.persist_path:
            with open(self.persist_path, "a") as f:
                f.write(record.to_json() + "\n")

    def summary(self) -> Dict[str, Any]:
        successes = [c for c in self.calls if c.error is None]
        failures = [c for c in self.calls if c.error is not None]

        def sum_usage(key: str) -> int:
            return sum((c.usage or {}).get(key) or 0 for c in successes)

        return {
            "total_llm_calls": len(self.calls),
            "successful_calls": len(successes),
            "failed_calls": len(failures),
            "truncation_retries": sum(1 for c in self.calls if c.truncation_attempt > 0),
            "network_retries": sum(1 for c in self.calls if c.network_attempt > 0),
            "total_prompt_tokens": sum_usage("prompt_tokens"),
            "total_completion_tokens": sum_usage("completion_tokens"),
            "total_tokens": sum_usage("total_tokens"),
            "total_wall_seconds": round(sum(c.duration_seconds for c in self.calls), 2),
        }


class _CallHandle:
    """Lets the `with trace.call(...) as handle:` body hand the raw
    litellm response back to the context manager for recording."""

    def __init__(self) -> None:
        self.response: Any = None

    def set_response(self, response: Any) -> None:
        self.response = response


def redact_request(kwargs: Dict[str, Any]) -> Dict[str, Any]:
    """The exact payload sent to litellm, minus the API key -- never
    persist a credential into a trace file."""
    return {k: v for k, v in kwargs.items() if k != "api_key"}
