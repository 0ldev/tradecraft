"""
Subprocess execution for DNS zone transfer (AXFR) via dig.
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class RawAxfrResult:
    nameserver: str
    stdout: str
    stderr: str
    returncode: int
    error: Optional[str] = None


def resolve_nameservers(target: str, timeout: int = 10) -> List[str]:
    """`dig NS <target> +short`, one hostname per output line, stripped
    of the trailing dot. Empty list if the command fails or returns
    nothing."""
    clean_target = target.strip()
    if not clean_target:
        return []

    argv = ["dig", "NS", clean_target, "+short"]
    try:
        proc = subprocess.run(
            argv,
            text=True,
            capture_output=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return []

    if proc.returncode != 0 or not proc.stdout:
        return []

    nameservers: List[str] = []
    for line in proc.stdout.splitlines():
        ns = line.strip().rstrip(".")
        if ns and ns not in nameservers:
            nameservers.append(ns)
    return nameservers


def attempt_transfer(target: str, nameserver: str, timeout: int = 10) -> RawAxfrResult:
    """`dig axfr <target> @<nameserver> +time=5 +tries=1`, one call per
    nameserver. RawAxfrResult{nameserver, stdout, stderr, returncode,
    error}. error set only on execute failure (dig not found, timeout
    hit at the subprocess level), not on a routine transfer rejection."""
    clean_target = target.strip()
    clean_ns = nameserver.strip()

    argv = ["dig", "axfr", clean_target, f"@{clean_ns}", "+time=5", "+tries=1"]
    try:
        proc = subprocess.run(
            argv,
            text=True,
            capture_output=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
        return RawAxfrResult(
            nameserver=clean_ns,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            returncode=proc.returncode,
            error=None,
        )
    except FileNotFoundError:
        return RawAxfrResult(
            nameserver=clean_ns,
            stdout="",
            stderr="",
            returncode=-1,
            error="dig executable not found",
        )
    except subprocess.TimeoutExpired:
        return RawAxfrResult(
            nameserver=clean_ns,
            stdout="",
            stderr="",
            returncode=-1,
            error=f"dig timed out after {timeout}s",
        )
    except Exception as exc:
        return RawAxfrResult(
            nameserver=clean_ns,
            stdout="",
            stderr="",
            returncode=-1,
            error=str(exc),
        )


def execute(target: str, timeout: int = 10) -> Dict[str, RawAxfrResult]:
    """Resolves nameservers via resolve_nameservers(), then calls
    attempt_transfer() against each sequentially. Returns
    {nameserver: RawAxfrResult}."""
    nameservers = resolve_nameservers(target, timeout=timeout)
    if not nameservers:
        return {}

    results: Dict[str, RawAxfrResult] = {}
    for ns in nameservers:
        results[ns] = attempt_transfer(target, ns, timeout=timeout)
    return results
