"""
Raw execution: builds the nuclei argv and runs it against one target. No
parsing here -- that's parse.py's job.
"""
from __future__ import annotations

import shutil
import subprocess
import urllib.parse
from dataclasses import dataclass
from typing import List, Optional

from tradecraft.adapters.partial_output import from_timeout


@dataclass
class RawNucleiResult:
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    target_url: str = ""
    error: Optional[str] = None
    # True when the subprocess was killed at its timeout. stdout/stderr then
    # hold only what was written before the kill.
    timed_out: bool = False
    timeout_seconds: Optional[int] = None


def normalize_target_url(target: str) -> str:
    target = target.strip()
    if not target:
        return ""
    if not (target.startswith("http://") or target.startswith("https://")):
        parsed = urllib.parse.urlsplit("//" + target)
        if parsed.port == 80:
            target = f"http://{target}"
        else:
            target = f"https://{target}"
    return target


def build_argv(
    target_url: str,
    tags: str = "cve,misconfig,exposure,tech",
    severity: str = "low,medium,high,critical",
    templates: str = "",
    rate_limit: int = 50,
    concurrency: int = 10,
    timeout: int = 10,
) -> List[str]:
    argv = [
        "nuclei",
        "-target",
        target_url,
        "-silent",
        "-jsonl",
        "-omit-raw",
        "-exclude-tags",
        "dos,fuzz",
        "-rl",
        str(max(1, rate_limit)),
        "-c",
        str(max(1, concurrency)),
        "-timeout",
        str(max(1, timeout)),
    ]
    if tags.strip():
        argv.extend(["-tags", tags.strip()])
    if severity.strip():
        argv.extend(["-severity", severity.strip()])
    if templates.strip():
        argv.extend(["-t", templates.strip()])
    return argv


def execute(
    target: str,
    tags: str = "cve,misconfig,exposure,tech",
    severity: str = "low,medium,high,critical",
    templates: str = "",
    rate_limit: int = 50,
    concurrency: int = 10,
    timeout_per_request: int = 10,
    overall_timeout: Optional[int] = None,
) -> RawNucleiResult:
    target_url = normalize_target_url(target)
    if not target_url:
        return RawNucleiResult(error="empty target")

    if shutil.which("nuclei") is None:
        return RawNucleiResult(target_url=target_url, error="nuclei binary not found on PATH")

    effective_timeout = overall_timeout if overall_timeout is not None else 180
    argv = build_argv(
        target_url=target_url,
        tags=tags,
        severity=severity,
        templates=templates,
        rate_limit=rate_limit,
        concurrency=concurrency,
        timeout=timeout_per_request,
    )

    try:
        proc = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=effective_timeout,
        )
        return RawNucleiResult(
            stdout=proc.stdout,
            stderr=proc.stderr,
            returncode=proc.returncode,
            target_url=target_url,
            error=f"nuclei exited with status {proc.returncode}" if proc.returncode != 0 else None,
        )
    except subprocess.TimeoutExpired as exc:
        # -jsonl writes one finding per line as it goes, so what was captured
        # before the kill is real (if incomplete) output.
        stdout, stderr = from_timeout(exc)
        return RawNucleiResult(
            stdout=stdout,
            stderr=stderr,
            target_url=target_url,
            timed_out=True,
            timeout_seconds=effective_timeout,
            error=f"nuclei timed out after {effective_timeout}s",
        )
    except Exception as exc:
        return RawNucleiResult(
            target_url=target_url,
            error=f"{type(exc).__name__}: {exc}",
        )
