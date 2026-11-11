from __future__ import annotations

from typing import Any, Dict, List, Tuple

from tradecraft.adapters.gitdumper.execute import execute as run_gitdumper
from tradecraft.adapters.gitdumper.parse import (
    host_port_from_target,
    parse_gitdumper_output,
)
from tradecraft.tools.base import Tool


class GitDumper(Tool):
    tool_id = "gitdumper"

    def run(
        self,
        target: str,
        jobs: int = 5,
        retry: int = 2,
    ) -> Dict[str, Any]:
        raw = run_gitdumper(target=target, jobs=jobs, retry=retry)
        if raw.error:
            return {
                "target": target,
                "git_exposed": False,
                "total_files_recovered": 0,
                "files": [],
                "error": raw.error,
            }

        parsed = parse_gitdumper_output(
            stdout=raw.stdout,
            stderr=raw.stderr,
            recovered_files=raw.recovered_files,
            git_commits=raw.git_commits,
            target_url=raw.target_url,
        )

        files = parsed.get("files", [])
        res: Dict[str, Any] = {
            "target": target,
            "git_exposed": parsed.get("git_exposed", False),
            "total_files_recovered": parsed.get("total_files_recovered", 0),
            "recent_commits": parsed.get("recent_commits", []),
        }

        if len(files) > 15:
            res["files"] = files[:15]
            res["omitted_files"] = len(files) - 15
            res["note"] = (
                f"{len(files) - 15} more files omitted to conserve context. "
                "Use search_evidence to inspect details."
            )
        else:
            res["files"] = files

        res["_full_evidence"] = {
            "target": target,
            "git_exposed": parsed.get("git_exposed", False),
            "total_files_recovered": len(files),
            "files": files,
            "recent_commits": parsed.get("recent_commits", []),
            "raw_stdout": raw.stdout,
        }
        return res

    def extract_evidence(self, params: Dict[str, Any], result: Dict[str, Any]) -> Tuple[str, Any] | None:
        target = params.get("target", "")
        full = result.pop("_full_evidence", None)
        if not target or full is None:
            return None
        host, _ = host_port_from_target(target)
        canonical = host if host else target
        return canonical, full

    def extract_facts(self, params: Dict[str, Any], result: Dict[str, Any]) -> List[Dict[str, Any]]:
        target = params.get("target", "")
        if not target:
            return []
        host, port = host_port_from_target(target)
        git_exposed = result.get("git_exposed", False)
        total_files = result.get("total_files_recovered", 0)

        fact: Dict[str, Any] = {"host": host, "port": port}
        if git_exposed:
            fact["git_repository_exposed"] = True
        if total_files > 0:
            fact["git_recovered_files_count"] = total_files
        if result.get("evidence_id"):
            fact["evidence"] = result["evidence_id"]

        if len(fact) > 2:
            return [fact]
        return []
