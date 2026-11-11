from __future__ import annotations

import os
import shutil
from typing import Any, Dict, List, Tuple

from tradecraft.adapters.gitdorker import execute as gitdorker_execute
from tradecraft.adapters.gitdorker import parse as gitdorker_parse
from tradecraft.tools.base import Tool


class GitDorker(Tool):
    tool_id = "gitdorker"

    def is_available(self) -> bool:
        return (
            shutil.which("python3") is not None
            and os.path.isfile(gitdorker_execute.SCRIPT_PATH)
            and bool(os.environ.get("GITHUB_TOKEN"))
        )

    def run(self, target: str) -> Dict[str, Any]:
        raw = gitdorker_execute.execute(target)
        if raw.error:
            return {
                "target": target,
                "total_findings": 0,
                "findings": [],
                "error": raw.error,
            }

        findings = gitdorker_parse.parse_findings(raw.csv_rows)
        res: Dict[str, Any] = {
            "target": target,
            "total_findings": len(findings),
        }

        if len(findings) > 20:
            res["findings"] = findings[:20]
            res["omitted_findings"] = len(findings) - 20
            res["note"] = (
                f"{len(findings) - 20} more omitted -- use read_evidence to inspect all."
            )
        else:
            res["findings"] = findings

        res["_full_evidence"] = {
            "target": target,
            "total_findings": len(findings),
            "findings": findings,
        }
        return res

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        return target, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        # GitHub finding URLs are not (host, port) network assets.
        # The model reads findings directly and logs anything verified via log_finding/log_note.
        return []
