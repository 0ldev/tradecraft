"""
Post-run investigation console (tradecraft/reporting/console.py).

Provides an operator-facing read-only console (one-shot or REPL) over
a finished engagement run's persisted artifacts (log.txt, trace.jsonl,
evidence/, facts.json).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import litellm

from tradecraft.execution.loop import (
    DEFAULT_API_KEY,
    DEFAULT_BASE_URL,
    DEFAULT_MODEL,
    DEFAULT_TIMEOUT,
    MAX_NETWORK_RETRIES,
    _RETRYABLE_NETWORK_ERRORS,
)
from tradecraft.execution.run_dir import get_tradecraft_home, resolve_run_dir
from tradecraft.memory.evidence import EvidenceStore

SYSTEM_PROMPT_TEMPLATE = """You are answering an operator's questions about one finished,
already-completed security engagement run. You cannot run any scan or
touch any target -- you only have read-only tools over that run's own
saved files. Answer only from what these tools and the context below
actually return; say "the logs don't show that" rather than guessing.

--- Engagement log ---
{log_content}

--- Attack surface facts ---
{facts_content}"""

CONSOLE_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "read_evidence",
            "description": "Retrieve full, detailed evidence previously recorded for a specific target and tool in this run.",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Host or domain whose evidence to inspect, e.g. 'examplepaint.com.br'.",
                    },
                    "tool_id": {
                        "type": "string",
                        "description": "The tool that collected the evidence, e.g. 'testssl'.",
                    },
                },
                "required": ["target", "tool_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_evidence",
            "description": "Search across saved evidence files in this run for a keyword or string.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "String to search for across stored evidence (case-insensitive substring match).",
                    },
                    "target": {
                        "type": "string",
                        "description": "Optional host or domain to restrict the search to. If omitted, searches across all targets.",
                        "default": "",
                    },
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_turn_reasoning",
            "description": "Retrieve the model's reasoning, tool calls, and LLM call records for a specific turn in this run.",
            "parameters": {
                "type": "object",
                "properties": {
                    "turn": {
                        "type": "integer",
                        "description": "The turn number to inspect.",
                    },
                },
                "required": ["turn"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_log",
            "description": "Search engagement log lines (FINDING: and note: entries) for a query string.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Substring to search for in log.txt (case-insensitive).",
                    },
                },
                "required": ["query"],
            },
        },
    },
]


def resolve_console_run_dir(
    *,
    run_dir: str | Path | None = None,
    target: str | None = None,
    run: str | None = None,
    tradecraft_home: Path | None = None,
) -> Path:
    """Resolves the run directory from either --run-dir or --target [--run ...].
    Raises ValueError if both or neither are provided.
    Raises FileNotFoundError if the directory or log.txt does not exist."""
    if run_dir and target:
        raise ValueError("specify either --run-dir or --target, not both")
    if not run_dir and not target:
        raise ValueError("specify either --run-dir or --target")

    if run_dir:
        p = Path(run_dir).resolve()
        if not p.is_dir():
            raise FileNotFoundError(f"run directory '{run_dir}' does not exist")
        resolved = p
    else:
        run_ref = run or "latest"
        _, resolved = resolve_run_dir(target, run_ref, tradecraft_home=tradecraft_home)  # type: ignore[arg-type]
        resolved = resolved.resolve()

    log_path = resolved / "log.txt"
    if not log_path.is_file():
        raise FileNotFoundError(f"error: {resolved} has no log.txt -- not a valid run directory")

    return resolved


class InvestigationConsole:
    """Interactive or one-shot investigation console over one finished run directory."""

    def __init__(
        self,
        run_dir: Path,
        *,
        model: str = DEFAULT_MODEL,
        base_url: Optional[str] = DEFAULT_BASE_URL,
        api_key: Optional[str] = DEFAULT_API_KEY,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        self.run_dir = Path(run_dir).resolve()
        self.log_file = self.run_dir / "log.txt"
        if not self.log_file.is_file():
            raise FileNotFoundError(f"error: {self.run_dir} has no log.txt -- not a valid run directory")

        self.model = model
        self.base_url = base_url
        self.api_key = api_key
        self.timeout = timeout

        self.evidence_dir = self.run_dir / "evidence"
        self.trace_file = self.run_dir / "trace.jsonl"
        self.facts_file = self.run_dir / "facts.json"

        self.system_prompt = self._build_system_prompt()
        self.conversation: List[Dict[str, Any]] = [
            {"role": "system", "content": self.system_prompt}
        ]

    def _build_system_prompt(self) -> str:
        log_content = self.log_file.read_text(encoding="utf-8")

        if self.facts_file.is_file():
            try:
                facts_data = json.loads(self.facts_file.read_text(encoding="utf-8"))
                facts_content = json.dumps(facts_data, indent=2)
            except Exception:
                facts_content = "(no attack-surface summary available for this run -- ask via search_log or read_evidence instead)"
        else:
            facts_content = "(no attack-surface summary available for this run -- ask via search_log or read_evidence instead)"

        return SYSTEM_PROMPT_TEMPLATE.format(
            log_content=log_content,
            facts_content=facts_content,
        )

    def read_evidence(self, target: str, tool_id: str) -> Dict[str, Any]:
        """Reads detailed tool evidence for target and tool_id."""
        if not self.evidence_dir.is_dir():
            return {"error": "no evidence directory found in this run"}
        store = EvidenceStore(persist_dir=self.evidence_dir)
        return store.read(target=target, tool_id=tool_id)

    def search_evidence(self, query: str, target: str = "") -> Dict[str, Any]:
        """Searches saved evidence files for query string."""
        if not self.evidence_dir.is_dir():
            return {"error": "no evidence directory found in this run"}
        store = EvidenceStore(persist_dir=self.evidence_dir)
        return store.search(query=query, target=target if target else None)

    def get_turn_reasoning(self, turn: int) -> Dict[str, Any]:
        """Reads trace.jsonl and returns CallRecord fields for the specified turn."""
        if not self.trace_file.is_file():
            return {"error": "no trace file found in this run"}

        matching_calls: List[Dict[str, Any]] = []
        with open(self.trace_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except Exception:
                    continue

                if record.get("turn") == turn:
                    matching_calls.append({
                        "index": record.get("index"),
                        "turn": record.get("turn"),
                        "call_kind": record.get("call_kind"),
                        "truncation_attempt": record.get("truncation_attempt"),
                        "network_attempt": record.get("network_attempt"),
                        "reasoning_content": record.get("reasoning_content"),
                        "content": record.get("content"),
                        "tool_call_names": record.get("tool_call_names"),
                        "tool_calls": record.get("tool_calls") or [],
                        "finish_reason": record.get("finish_reason"),
                    })

        matching_calls.sort(key=lambda c: c.get("index", 0) if c.get("index") is not None else 0)
        return {"turn": turn, "calls": matching_calls}

    def search_log(self, query: str) -> List[str]:
        """Returns log lines containing query (case-insensitive)."""
        if not self.log_file.is_file():
            return []

        q_lower = query.lower()
        matches: List[str] = []
        with open(self.log_file, "r", encoding="utf-8") as f:
            for line in f:
                clean = line.rstrip("\r\n")
                if q_lower in clean.lower():
                    matches.append(clean)
        return matches

    def dispatch_tool(self, name: str, args: Dict[str, Any]) -> Any:
        """Executes a console read-only tool by name with arguments."""
        if name == "read_evidence":
            return self.read_evidence(
                target=args.get("target", ""),
                tool_id=args.get("tool_id", ""),
            )
        elif name == "search_evidence":
            return self.search_evidence(
                query=args.get("query", ""),
                target=args.get("target", ""),
            )
        elif name == "get_turn_reasoning":
            turn = args.get("turn")
            if turn is None:
                return {"error": "turn parameter is required"}
            return self.get_turn_reasoning(turn=int(turn))
        elif name == "search_log":
            return self.search_log(query=args.get("query", ""))
        else:
            return {"error": f"unknown tool '{name}'"}

    def _complete_call(self) -> Any:
        """Invokes litellm.completion with network retry."""
        kwargs: Dict[str, Any] = {
            "model": self.model,
            "messages": self.conversation,
            "tools": CONSOLE_TOOLS,
            "timeout": self.timeout,
        }
        if self.base_url:
            kwargs["api_base"] = self.base_url
        if self.api_key:
            kwargs["api_key"] = self.api_key

        last_exc: Optional[Exception] = None
        for _ in range(MAX_NETWORK_RETRIES + 1):
            try:
                return litellm.completion(**kwargs)
            except _RETRYABLE_NETWORK_ERRORS as exc:
                last_exc = exc
        if last_exc:
            raise last_exc
        raise RuntimeError("network call failed with no exception")

    def ask(self, question: str, max_tool_turns: int = 10) -> str:
        """Sends one user question and runs tool loops to completion.
        Returns the final assistant message content."""
        self.conversation.append({"role": "user", "content": question})

        turns = 0
        while turns < max_tool_turns:
            turns += 1
            response = self._complete_call()
            message = response.choices[0].message
            tool_calls = getattr(message, "tool_calls", None)

            assistant_entry: Dict[str, Any] = {
                "role": "assistant",
                "content": message.content or "",
            }
            if tool_calls:
                assistant_entry["tool_calls"] = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments,
                        },
                    }
                    for tc in tool_calls
                ]
            if getattr(message, "reasoning_content", None):
                assistant_entry["reasoning_content"] = message.reasoning_content

            self.conversation.append(assistant_entry)

            if not tool_calls:
                return message.content or ""

            for tc in tool_calls:
                func_name = tc.function.name
                func_args_raw = tc.function.arguments
                if isinstance(func_args_raw, str):
                    try:
                        func_args = json.loads(func_args_raw)
                    except Exception:
                        func_args = {}
                elif isinstance(func_args_raw, dict):
                    func_args = func_args_raw
                else:
                    func_args = {}

                result = self.dispatch_tool(func_name, func_args)
                self.conversation.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "name": func_name,
                    "content": json.dumps(result, default=str),
                })

        return "(investigation reached maximum tool-call turns)"


def run_repl(console: InvestigationConsole) -> None:
    """Interactive REPL reading questions from stdin in an ongoing conversation."""
    found: List[str] = []
    if console.log_file.is_file():
        found.append("log.txt")
    if console.trace_file.is_file():
        found.append("trace.jsonl")
    if console.evidence_dir.is_dir():
        found.append("evidence/")
    if console.facts_file.is_file():
        found.append("facts.json")

    found_str = ", ".join(found) if found else "none"
    print(f"Tradecraft Console: {console.run_dir} (found: {found_str})")

    while True:
        try:
            user_input = input("\ntradecraft> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        if not user_input:
            continue
        if user_input.lower() in ("exit", "quit"):
            break

        answer = console.ask(user_input)
        print(f"\n{answer}")
