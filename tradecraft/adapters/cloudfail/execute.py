"""
Raw execution: builds the cloudfail argv and runs it against a target domain.
No parsing here -- that's parse.py's job.
"""
from __future__ import annotations

import shutil
import subprocess
import urllib.parse
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class RawCloudfailResult:
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    target: str = ""
    error: Optional[str] = None


def normalize_target(target: str) -> str:
    """Extract clean domain/host name from target string or URL."""
    target = target.strip()
    if not target:
        return ""
    if "://" in target:
        parsed = urllib.parse.urlsplit(target)
        host = parsed.hostname or target
    else:
        host = target.split("/")[0].split(":")[0]
    return host.strip()


def build_argv(
    target: str,
    subdomains: str = "subdomains_top100.txt",
) -> List[str]:
    """Builds the cloudfail invocation argv."""
    clean_target = normalize_target(target)
    argv = ["cloudfail", "-t", clean_target]
    if subdomains.strip():
        argv.extend(["-s", subdomains.strip()])
    return argv


def execute(
    target: str,
    subdomains: str = "subdomains_top100.txt",
    timeout: int = 60,
) -> RawCloudfailResult:
    """Executes cloudfail against a target domain."""
    clean_target = normalize_target(target)
    if not clean_target:
        return RawCloudfailResult(error="empty target domain")

    if shutil.which("cloudfail") is None:
        return RawCloudfailResult(target=clean_target, error="cloudfail binary not found on PATH")

    argv = build_argv(target=clean_target, subdomains=subdomains)

    try:
        proc = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return RawCloudfailResult(
            stdout=proc.stdout,
            stderr=proc.stderr,
            returncode=proc.returncode,
            target=clean_target,
        )
    except subprocess.TimeoutExpired:
        return RawCloudfailResult(
            target=clean_target,
            error=f"cloudfail timed out after {timeout}s",
        )
    except Exception as exc:
        return RawCloudfailResult(
            target=clean_target,
            error=f"{type(exc).__name__}: {exc}",
        )
