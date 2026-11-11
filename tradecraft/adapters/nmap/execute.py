"""
Raw execution: builds the nmap argv and runs it. Does no parsing of the
output -- that's `parse.py`'s job, kept separate so each half can be
tested without the other (argv construction without mocking subprocess
timing, output parsing without ever shelling out).
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Optional


@dataclass
class RawScanResult:
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    error: Optional[str] = None  # set only on a genuine execution failure


def parse_host_port(target: str) -> tuple[str, Optional[int]]:
    """'host:port' -> (host, port); plain 'host' -> (host, None)."""
    if ":" in target and target.count(":") == 1:
        host, _, port_str = target.rpartition(":")
        if port_str.isdigit():
            return host, int(port_str)
    return target, None


def build_argv(target: str, depth: str = "standard") -> tuple[list[str], str]:
    """Returns (argv, resolved_host). Strict, hand-picked flags only --
    the LLM chooses `target`/`depth`, never raw flags."""
    host, explicit_port = parse_host_port(target)

    if explicit_port is not None:
        flags = ["-sV", "-p", str(explicit_port)]
    elif depth == "quick":
        flags = ["-F"]
    else:
        flags = ["-sV", "--top-ports", "1000"]

    argv = ["nmap", "-Pn", "-T4", "--max-retries", "2", "-oG", "-"] + flags + [host]
    return argv, host


def execute(target: str, depth: str = "standard", timeout: int = 300) -> RawScanResult:
    argv, _ = build_argv(target, depth)
    try:
        process = subprocess.run(argv, text=True, capture_output=True, timeout=timeout, stdin=subprocess.DEVNULL)
    except FileNotFoundError:
        return RawScanResult(error="nmap executable not found")
    except subprocess.TimeoutExpired:
        return RawScanResult(error=f"nmap timed out after {timeout}s")

    if process.returncode != 0:
        return RawScanResult(
            stdout=process.stdout,
            stderr=process.stderr,
            returncode=process.returncode,
            error=f"nmap failed: {process.stderr.strip()}",
        )

    return RawScanResult(stdout=process.stdout, stderr=process.stderr, returncode=0)
