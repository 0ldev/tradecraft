"""
Tool contract for Tradecraft.

A `Tool` glues a YAML contract (`config/tools/<tool_id>.yaml`, loaded via
`spec_loader`) to an implementation's `run()`. A tool here just returns a
plain dict, which goes straight back into the conversation as the
tool_result the model reads next turn.

Subclasses set `tool_id` and implement `run()` only -- name, description,
parameter schema, required binary, and scope-sensitivity all come from
the YAML file, not from Python, so there is exactly one place each of
those facts is declared. See `domain.py` and `docs/tools.md` for where
tool-specific execution logic belongs instead (tradecraft/adapters/).
"""
from __future__ import annotations

import shutil
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Tuple

from tradecraft.domain import ToolSpec
from tradecraft.tools.spec_loader import (
    load_destructive_categories,
    load_destructive_flag,
    load_required_binary,
    load_scope_param,
    load_spec,
)

__all__ = ["Tool", "ToolSpec"]


class Tool(ABC):
    """Base class for a Tradecraft tool. Subclasses set `tool_id` and
    implement `run(**params) -> dict`.

    Use the "error" key only for a genuine failure to execute (binary
    missing, process crashed, timed out) -- a successful run that simply
    found nothing goes in "result" with an empty/zero finding, never in
    "error".
    """

    tool_id: str

    @property
    def spec(self) -> ToolSpec:
        return load_spec(self.tool_id)

    @property
    def required_binary(self) -> str | None:
        return load_required_binary(self.tool_id)

    @property
    def scope_param(self) -> str | None:
        """Name of the parameter (if any) that carries the network target
        this tool acts against. The execution loop scope-checks that
        parameter before calling the tool."""
        return load_scope_param(self.tool_id)

    @property
    def destructive(self) -> bool:
        """True if this tool's own contract declares destructive: true
        -- it can mutate target state in a way that doesn't undo itself.
        Gated by --allow-destructive at the CLI level (tradecraft/policy/
        destructive.py), never read elsewhere."""
        return load_destructive_flag(self.tool_id)

    @property
    def destructive_categories(self) -> frozenset[str]:
        """Blast-radius categories this tool's contract declares under
        destructive_categories: (see docs/policy.md) -- empty for a
        non-destructive tool. A destructive tool with more than one
        category requires every one of them to be
        opted into (tradecraft/policy/destructive.py's ALL-semantics)."""
        return load_destructive_categories(self.tool_id)

    def is_available(self) -> bool:
        if self.required_binary is None:
            return True
        return shutil.which(self.required_binary) is not None

    @abstractmethod
    def run(self, **params: Any) -> Dict[str, Any]: ...

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Return deterministic (host, port) facts this call's result
        reports, for the execution loop to merge into the FactStore
        right after dispatch (`tradecraft/memory/facts.py`). Each returned
        dict needs "host" and "port"; every other key is a field to
        merge onto that port's record. Default: no facts -- a tool with
        no per-port/service data (e.g. the memory tools) doesn't need to
        override this."""
        return []

    def extract_evidence(
        self, params: Dict[str, Any], result: Dict[str, Any]
    ) -> Tuple[str, Any] | Tuple[str, Any, List[str]] | None:
        """Return (target, data) if this tool call produced detailed evidence
        that should be persisted to disk outside the conversation history
        (tradecraft/memory/evidence.py).

        By default, if the tool has a target/url/host parameter and produced a
        successful result dict, persist the result under that target so findings
        citing this tool result are verifiable against EvidenceStore.
        Tools with custom offloading logic or batch targets override this.
        """
        if not isinstance(result, dict) or result.get("error"):
            return None
        if self.tool_id in (
            "log_note",
            "log_finding",
            "retract_finding",
            "recall_memory",
            "read_evidence",
            "search_evidence",
        ):
            return None

        target = ""
        if hasattr(self, "spec") and self.spec and getattr(self.spec, "scope_param", None):
            target = str(params.get(self.spec.scope_param) or "").strip()
        if not target:
            for candidate in ("target", "url", "host", "domain", "ip"):
                val = params.get(candidate)
                if val and isinstance(val, str) and val.strip():
                    target = val.strip()
                    break
        if not target:
            return None
        return target, result

    def __call__(self, **params: Any) -> Dict[str, Any]:
        if not self.is_available():
            return {"error": f"required binary '{self.required_binary}' not found on PATH"}
        try:
            return self.run(**params)
        except Exception as exc:  # noqa: BLE001 - surfaced to the model as a tool error
            return {"error": f"{type(exc).__name__}: {exc}"}
