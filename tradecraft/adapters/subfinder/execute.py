from __future__ import annotations

import subprocess
from dataclasses import dataclass


@dataclass
class RawDiscoveryResult:
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    error: str | None = None


def build_argv(target: str) -> list[str]:
    return ["subfinder", "-d", target, "-silent", "-all"]


def execute(target: str, timeout: int = 120) -> RawDiscoveryResult:
    try:
        process = subprocess.run(
            build_argv(target), text=True, capture_output=True, timeout=timeout, stdin=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        return RawDiscoveryResult(error="subfinder executable not found")
    except subprocess.TimeoutExpired:
        return RawDiscoveryResult(error=f"subfinder timed out after {timeout}s")

    return RawDiscoveryResult(
        stdout=process.stdout,
        stderr=process.stderr,
        returncode=process.returncode,
        error=f"subfinder failed: {process.stderr.strip()}" if process.returncode else None,
    )