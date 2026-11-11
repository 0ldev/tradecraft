"""
Raw execution: builds the searchsploit argv and executes queries or path lookups.
No parsing logic here -- that's parse.py's job.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class RawSearchsploitResult:
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    query: str = ""
    cve: str = ""
    edb_id: str = ""
    file_content: str = ""
    file_path: str = ""
    error: Optional[str] = None


def build_argv(
    query: str = "",
    cve: str = "",
    edb_id: str = "",
) -> List[str]:
    """Builds the searchsploit command-line invocation."""
    if edb_id.strip():
        return ["searchsploit", "-p", edb_id.strip()]
    if cve.strip():
        clean_cve = cve.strip()
        if clean_cve.upper().startswith("CVE-"):
            clean_cve = clean_cve[4:]
        return ["searchsploit", "-j", "--cve", clean_cve]
    if query.strip():
        # Pass terms individually for AND matching
        terms = [t for t in query.strip().split() if t]
        return ["searchsploit", "-j", *terms]
    return ["searchsploit", "-h"]


def execute(
    query: str = "",
    cve: str = "",
    edb_id: str = "",
    timeout: int = 30,
) -> RawSearchsploitResult:
    """Executes searchsploit search or inspection."""
    if not query.strip() and not cve.strip() and not edb_id.strip():
        return RawSearchsploitResult(error="at least one of 'query', 'cve', or 'edb_id' must be specified")

    if shutil.which("searchsploit") is None:
        return RawSearchsploitResult(
            query=query,
            cve=cve,
            edb_id=edb_id,
            error="searchsploit binary not found on PATH",
        )

    argv = build_argv(query=query, cve=cve, edb_id=edb_id)

    try:
        proc = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        file_content = ""
        file_path = ""

        # If examining a specific EDB-ID, extract path and read PoC
        if edb_id.strip() and proc.returncode == 0:
            path_match = re.search(r"Path:\s*([^\r\n]+)", proc.stdout)
            if path_match:
                candidate_path = path_match.group(1).strip()
                if os.path.isfile(candidate_path):
                    file_path = candidate_path
                    try:
                        with open(candidate_path, "r", encoding="utf-8", errors="replace") as f:
                            file_content = f.read(4000)
                    except Exception as e:
                        file_content = f"Error reading exploit file: {e}"

        return RawSearchsploitResult(
            stdout=proc.stdout,
            stderr=proc.stderr,
            returncode=proc.returncode,
            query=query,
            cve=cve,
            edb_id=edb_id,
            file_content=file_content,
            file_path=file_path,
        )
    except subprocess.TimeoutExpired:
        return RawSearchsploitResult(
            query=query,
            cve=cve,
            edb_id=edb_id,
            error=f"searchsploit timed out after {timeout}s",
        )
    except Exception as exc:
        return RawSearchsploitResult(
            query=query,
            cve=cve,
            edb_id=edb_id,
            error=f"{type(exc).__name__}: {exc}",
        )
