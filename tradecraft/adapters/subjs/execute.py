"""
Raw execution: builds the subjs argv and runs it against one target.
No parsing here -- see parse.py.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from typing import Optional


@dataclass
class RawSubjsResult:
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    error: Optional[str] = None


def normalize_url(target: str) -> str:
    """Bare host/'host:port' -> a URL. Defaults to http:// unless scheme is already present."""
    target = target.strip()
    if target.startswith("http://") or target.startswith("https://"):
        return target
    return f"http://{target}"


def build_argv() -> list[str]:
    return ["subjs"]


def execute(target: str, timeout: int = 120) -> RawSubjsResult:
    target = target.strip()
    if not target:
        return RawSubjsResult(error="Target cannot be empty")

    binary = shutil.which("subjs")
    if not binary:
        return RawSubjsResult(error="subjs executable not found on PATH")

    target_url = normalize_url(target)

    try:
        proc = subprocess.run(
            build_argv(),
            input=target_url + "\n",
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return RawSubjsResult(
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            returncode=proc.returncode,
        )
    except FileNotFoundError:
        return RawSubjsResult(error="subjs executable not found on PATH")
    except subprocess.TimeoutExpired:
        return RawSubjsResult(error=f"subjs timed out after {timeout}s")
    except Exception as exc:
        return RawSubjsResult(error=f"subjs execution failed: {str(exc)}")
