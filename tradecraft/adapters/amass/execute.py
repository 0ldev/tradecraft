from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Optional

AMASS_INTERNAL_TIMEOUT_MINUTES = 3
SUBPROCESS_TIMEOUT_SECONDS = 240  # safety margin over the above, in case amass ignores its own flag


@dataclass
class RawAmassResult:
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    error: Optional[str] = None


def build_argv(target: str) -> list[str]:
    return [
        "amass",
        "enum",
        "-d",
        target,
        "-silent",
        "-active",
        "-timeout",
        str(AMASS_INTERNAL_TIMEOUT_MINUTES),
    ]


def execute(target: str, timeout: int = SUBPROCESS_TIMEOUT_SECONDS) -> RawAmassResult:
    try:
        proc = subprocess.run(
            build_argv(target),
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        return RawAmassResult(error="amass executable not found on PATH")
    except subprocess.TimeoutExpired:
        return RawAmassResult(
            error=(
                f"amass timed out after {timeout}s (internal "
                f"-timeout={AMASS_INTERNAL_TIMEOUT_MINUTES}m may have been exceeded or ignored)"
            )
        )

    return RawAmassResult(
        stdout=proc.stdout,
        stderr=proc.stderr,
        returncode=proc.returncode,
        error=f"amass failed: {proc.stderr.strip()}" if proc.returncode != 0 else None,
    )
