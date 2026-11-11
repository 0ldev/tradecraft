"""
Execution logic for coercer: scan remote Windows endpoints for coercive RPC methods
(PetitPotam/MS-EFSR, PrinterBug/MS-RPRN, DFSNM, ShadowCoerce).
"""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import List, Optional

DEFAULT_TIMEOUT_SECONDS = 90


@dataclass
class RawCoercerResult:
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    target: str = ""
    error: Optional[str] = None


def find_binary() -> Optional[str]:
    """Finds coercer binary on PATH."""
    return shutil.which("coercer")


def build_argv(
    target: str,
    domain: str = "",
    username: str = "",
    password: str = "",
    hashes: str = "",
    binary: str = "coercer",
) -> List[str]:
    """Builds non-destructive scan command for coercer."""
    cmd = [binary, "scan", "-t", target.strip()]
    if domain.strip():
        cmd.extend(["-d", domain.strip()])
    if username.strip():
        cmd.extend(["-u", username.strip()])
    if password.strip():
        cmd.extend(["-p", password.strip()])
    elif hashes.strip():
        cmd.extend(["--hashes", hashes.strip()])
    return cmd


def execute(
    target: str,
    domain: str = "",
    username: str = "",
    password: str = "",
    hashes: str = "",
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> RawCoercerResult:
    t = target.strip()
    if not t:
        return RawCoercerResult(error="empty target host")

    binary = find_binary()
    if not binary:
        return RawCoercerResult(target=t, error="coercer executable not found on PATH")

    argv = build_argv(
        target=t,
        domain=domain,
        username=username,
        password=password,
        hashes=hashes,
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
        return RawCoercerResult(
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            returncode=proc.returncode,
            target=t,
        )
    except FileNotFoundError:
        return RawCoercerResult(target=t, error="coercer executable not found on PATH")
    except subprocess.TimeoutExpired:
        return RawCoercerResult(target=t, error=f"coercer timed out after {timeout}s")
    except Exception as exc:
        return RawCoercerResult(target=t, error=f"coercer execution failed: {exc}")
