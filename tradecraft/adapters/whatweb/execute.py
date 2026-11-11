"""
Raw execution: builds the whatweb argv and runs it against one target.
No parsing here -- see parse.py.
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Optional


@dataclass
class RawFingerprintResult:
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    error: Optional[str] = None


def to_url(target: str) -> str:
    """Bare host/'host:port' -> a URL. whatweb needs an explicit scheme;
    default to https only when the target makes that port explicit."""
    if target.startswith("http://") or target.startswith("https://"):
        return target
    if target.rsplit(":", 1)[-1] == "443":
        return f"https://{target}"
    return f"http://{target}"


def build_argv(url: str) -> list[str]:
    return ["whatweb", "--log-json=-", "-q", url]


def execute(target: str, timeout: int = 60) -> RawFingerprintResult:
    try:
        process = subprocess.run(
            build_argv(to_url(target)), text=True, capture_output=True, timeout=timeout, stdin=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        return RawFingerprintResult(error="whatweb executable not found")
    except subprocess.TimeoutExpired:
        return RawFingerprintResult(error=f"whatweb timed out after {timeout}s")

    return RawFingerprintResult(stdout=process.stdout, stderr=process.stderr, returncode=process.returncode)
