"""
Subprocess execution for LinkFinder. Runs LinkFinder against a target URL
using the -d (domain crawl) flag and outputs raw CLI text.
"""
from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from typing import Optional

SCRIPT_CANDIDATES = (
    "/opt/LinkFinder/linkfinder.py",
    os.path.expanduser("~/LinkFinder/linkfinder.py"),
)


@dataclass
class RawLinkfinderResult:
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    target_url: str = ""
    error: Optional[str] = None


def find_script() -> Optional[str]:
    return next((p for p in SCRIPT_CANDIDATES if os.path.isfile(p)), None)


def normalize_target_url(target: str) -> str:
    target = target.strip()
    if not target:
        return ""
    if not (target.startswith("http://") or target.startswith("https://")):
        target = f"https://{target}"
    return target


def execute(target: str, timeout: int = 180) -> RawLinkfinderResult:
    target_url = normalize_target_url(target)
    if not target_url:
        return RawLinkfinderResult(error="Empty target")

    script = find_script()
    if not script:
        return RawLinkfinderResult(
            target_url=target_url,
            error=f"LinkFinder not found at any of: {', '.join(SCRIPT_CANDIDATES)}",
        )

    cmd = ["python3", script, "-i", target_url, "-d", "-o", "cli"]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
        return RawLinkfinderResult(
            stdout=proc.stdout,
            stderr=proc.stderr,
            returncode=proc.returncode,
            target_url=target_url,
        )
    except FileNotFoundError:
        return RawLinkfinderResult(target_url=target_url, error="python3 binary not found")
    except subprocess.TimeoutExpired:
        return RawLinkfinderResult(target_url=target_url, error="LinkFinder execution timed out")
