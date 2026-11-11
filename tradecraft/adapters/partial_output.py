"""Recover the output a subprocess produced before it was killed.

When subprocess.run(..., timeout=N) expires, the TimeoutExpired exception
carries whatever stdout/stderr the child had written so far. Throwing that
away makes a slow run look like one that found nothing. Adapters use this
to keep the partial output and report that the run was cut short.

Pure helpers, no I/O.
"""
from __future__ import annotations

import subprocess
from typing import Tuple, Union


def captured_text(value: Union[bytes, str, None]) -> str:
    """TimeoutExpired may hold bytes even when the call used text=True
    (CPython behavior varies by version), so normalize to str."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def from_timeout(exc: subprocess.TimeoutExpired) -> Tuple[str, str]:
    """(stdout, stderr) captured before the timeout, as text."""
    return captured_text(exc.stdout), captured_text(exc.stderr)
