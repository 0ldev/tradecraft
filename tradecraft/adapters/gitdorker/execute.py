"""
Raw execution: builds the GitDorker argv and runs it against a target query.
No parsing here -- that's parse.py's job.
"""
from __future__ import annotations

import csv
import os
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import List, Optional

SCRIPT_PATH = "/opt/gitdorker/GitDorker.py"
WORDLIST_PATH = "/opt/gitdorker/Dorks/alldorksv3"


@dataclass
class RawGitdorkerResult:
    csv_rows: List[List[str]] = field(default_factory=list)
    error: Optional[str] = None


def execute(target: str, timeout: int = 600) -> RawGitdorkerResult:
    t = target.strip()
    if not t:
        return RawGitdorkerResult(error="empty target")

    token = os.environ.get("GITHUB_TOKEN")
    if not token or not token.strip():
        return RawGitdorkerResult(error="GITHUB_TOKEN environment variable not set")

    if not os.path.isfile(SCRIPT_PATH):
        return RawGitdorkerResult(error=f"GitDorker not found at {SCRIPT_PATH}")

    if not os.path.isfile(WORDLIST_PATH):
        return RawGitdorkerResult(error=f"GitDorker wordlist not found at {WORDLIST_PATH}")

    out_fd, out_path = tempfile.mkstemp(suffix=".csv", prefix="tradecraft_gitdorker_")
    os.close(out_fd)

    cmd = [
        "python3",
        SCRIPT_PATH,
        "-t",
        token.strip(),
        "-q",
        t,
        "-d",
        WORDLIST_PATH,
        "-o",
        out_path,
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )

        rows: List[List[str]] = []
        if os.path.exists(out_path) and os.path.getsize(out_path) > 0:
            with open(out_path, "r", encoding="utf-8", errors="replace") as f:
                reader = csv.reader(f)
                for row in reader:
                    if row:
                        rows.append(row)

        return RawGitdorkerResult(csv_rows=rows)
    except subprocess.TimeoutExpired:
        return RawGitdorkerResult(error="GitDorker execution timed out")
    except Exception as exc:
        return RawGitdorkerResult(error=f"{type(exc).__name__}: {exc}")
    finally:
        if os.path.exists(out_path):
            try:
                os.remove(out_path)
            except OSError:
                pass
