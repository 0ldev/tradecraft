"""
Raw execution: builds the kiterunner (kr) argv and runs it against a target endpoint.
No parsing here -- that's parse.py's job.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import urllib.parse
from dataclasses import dataclass
from typing import List, Optional

from tradecraft.adapters.wordlists import resolve_wordlist


@dataclass
class RawKiterunnerResult:
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    target_url: str = ""
    error: Optional[str] = None


def normalize_target_url(target: str) -> str:
    """Normalize target to ensure a valid HTTP/HTTPS URL scheme."""
    target = target.strip()
    if not target:
        return ""
    if not target.startswith(("http://", "https://")):
        parsed = urllib.parse.urlsplit("//" + target)
        if parsed.port == 80:
            target = f"http://{target}"
        else:
            target = f"https://{target}"
    return target


def find_kiterunner_binary() -> Optional[str]:
    """Finds either kr or kiterunner binary on PATH."""
    return shutil.which("kr") or shutil.which("kiterunner")


def build_argv(
    target_url: str,
    wordlist_path: str,
    max_connections: int = 5,
    binary: str = "kr",
) -> List[str]:
    """Builds the kiterunner command-line invocation."""
    argv = [
        binary,
        "scan",
        target_url,
        "-w",
        wordlist_path,
        "--kitebuilder-full-scan",
        "--progress=false",
        "-q",
        "-x",
        str(max(1, max_connections)),
        "-o",
        "json",
    ]
    return argv


def execute(
    target: str,
    wordlist: str = "api-routes.kite",
    max_connections: int = 5,
    timeout: int = 60,
) -> RawKiterunnerResult:
    """Executes kiterunner against a target URL."""
    target_url = normalize_target_url(target)
    if not target_url:
        return RawKiterunnerResult(error="empty target URL")

    binary = find_kiterunner_binary()
    if binary is None:
        return RawKiterunnerResult(target_url=target_url, error="kiterunner (kr) binary not found on PATH")

    wordlist_path = resolve_wordlist(wordlist, fallback="api-routes.kite")
    if not os.path.isfile(wordlist_path):
        return RawKiterunnerResult(target_url=target_url, error=f"kiterunner wordlist not found: {wordlist_path}")

    argv = build_argv(
        target_url=target_url,
        wordlist_path=wordlist_path,
        max_connections=max_connections,
        binary=binary,
    )

    try:
        proc = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return RawKiterunnerResult(
            stdout=proc.stdout,
            stderr=proc.stderr,
            returncode=proc.returncode,
            target_url=target_url,
        )
    except subprocess.TimeoutExpired:
        return RawKiterunnerResult(
            target_url=target_url,
            error=f"kiterunner timed out after {timeout}s",
        )
    except Exception as exc:
        return RawKiterunnerResult(
            target_url=target_url,
            error=f"{type(exc).__name__}: {exc}",
        )
