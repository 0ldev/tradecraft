"""
Execution logic for smuggler: HTTP request smuggling / desynchronization scanner.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import List, Optional

SCRIPT_CANDIDATES = (
    "/opt/smuggler/smuggler.py",
    os.path.expanduser("~/smuggler/smuggler.py"),
)
DEFAULT_TIMEOUT_SECONDS = 60


@dataclass
class RawSmugglerResult:
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    target_url: str = ""
    error: Optional[str] = None


def find_script() -> Optional[str]:
    """Finds smuggler.py script location."""
    for path in SCRIPT_CANDIDATES:
        if os.path.isfile(path):
            return path
    which = shutil.which("smuggler") or shutil.which("smuggler.py")
    if which:
        return which
    return None


def build_argv(script_path: str, target_url: str, timeout: int = 10) -> List[str]:
    """Builds smuggler execution command."""
    return [
        "python3",
        script_path,
        "-u",
        target_url.strip(),
        "-q",
        "-t",
        str(max(5, min(timeout, 30))),
    ]


def execute(target: str, timeout: int = DEFAULT_TIMEOUT_SECONDS) -> RawSmugglerResult:
    url = target.strip()
    if not url:
        return RawSmugglerResult(error="empty target URL")

    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    script = find_script()
    if not script:
        return RawSmugglerResult(target_url=url, error=f"smuggler script not found at {SCRIPT_CANDIDATES[0]}")

    argv = build_argv(script_path=script, target_url=url, timeout=10)

    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
        return RawSmugglerResult(
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            returncode=proc.returncode,
            target_url=url,
        )
    except FileNotFoundError:
        return RawSmugglerResult(target_url=url, error="python3 binary not found")
    except subprocess.TimeoutExpired:
        return RawSmugglerResult(target_url=url, error=f"smuggler execution timed out after {timeout}s")
    except Exception as exc:
        return RawSmugglerResult(target_url=url, error=f"smuggler execution failed: {exc}")
