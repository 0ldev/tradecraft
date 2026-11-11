"""
Non-destructive: one GET per datastore per candidate, no write attempted.
Belongs to profile 'cloud'.
"""
from __future__ import annotations

from typing import Any, Dict

from tradecraft.adapters.firebase_probe import execute as fb_execute
from tradecraft.adapters.firebase_probe import parse as fb_parse
from tradecraft.tools.base import Tool


class FirebaseProbe(Tool):
    tool_id = "firebase_probe"

    def run(self, project_ids: str, timeout: int = 10) -> Dict[str, Any]:
        raw = fb_execute.execute(project_ids=project_ids, timeout=timeout)
        return fb_parse.parse_firebase_result(raw)
