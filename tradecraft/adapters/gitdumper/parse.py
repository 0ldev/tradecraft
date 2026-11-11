"""
Pure parsing functions for git-dumper output.
No subprocess or I/O logic here.
"""
from __future__ import annotations

import urllib.parse
from typing import Any, Dict, List, Tuple


def host_port_from_target(target: str) -> Tuple[str, int]:
    """Extract (host, port) from a target URL or host string."""
    parsed = urllib.parse.urlsplit(target if "://" in target else f"//{target}")
    host = parsed.hostname or target
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return host, port


def parse_gitdumper_output(
    stdout: str,
    stderr: str = "",
    recovered_files: List[str] | None = None,
    git_commits: List[str] | None = None,
    target_url: str = "",
) -> Dict[str, Any]:
    """Parses git-dumper stdout/stderr and recovered files into structured results."""
    combined = f"{stdout}\n{stderr}"
    files = recovered_files or []
    commits = git_commits or []

    git_exposed = False
    if ".git/HEAD [200]" in combined or "Running git checkout" in combined or len(files) > 0 or len(commits) > 0:
        git_exposed = True
    elif "[404]" in combined or "[403]" in combined or "responded with status code 404" in combined:
        git_exposed = False

    return {
        "target": target_url,
        "git_exposed": git_exposed,
        "total_files_recovered": len(files),
        "files": files,
        "recent_commits": commits,
    }
