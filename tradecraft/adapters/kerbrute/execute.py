"""
Subprocess execution for kerbrute: runs userenum against a Domain Controller.
No parsing logic here -- see parse.py.
"""
from __future__ import annotations

import shutil
import subprocess
from typing import List, Optional

from tradecraft.adapters.kerbrute import parse as kb_parse
from tradecraft.adapters.wordlists import resolve_wordlist

DEFAULT_TIMEOUT = 120


def find_kerbrute_binary() -> Optional[str]:
    """Finds kerbrute binary on PATH."""
    return shutil.which("kerbrute")


def build_argv(
    target: str,
    domain: str,
    wordlist: str,
    safe: bool = True,
    binary: str = "kerbrute",
) -> List[str]:
    """Builds argv for `kerbrute userenum` invocation."""
    argv = [
        binary,
        "userenum",
        "--dc",
        target,
        "-d",
        domain,
    ]
    if safe:
        argv.append("--safe")
    argv.append(wordlist)
    return argv


def execute(
    target: str,
    domain: str,
    wordlist: str = "",
    safe: bool = True,
    timeout: int = DEFAULT_TIMEOUT,
    runner=None,
) -> kb_parse.RawKerbruteResult:
    """Executes kerbrute userenum against the target Domain Controller."""
    host = kb_parse.normalize_target_host(target)
    if not host:
        return kb_parse.RawKerbruteResult(error="empty target domain controller host")
    if not domain or not domain.strip():
        return kb_parse.RawKerbruteResult(target=host, error="missing required Active Directory domain")

    binary = find_kerbrute_binary()
    if binary is None:
        return kb_parse.RawKerbruteResult(
            target=host, domain=domain, error="kerbrute binary not found on PATH"
        )

    clean_domain = domain.strip()
    run_cmd = runner or subprocess.run

    # Resolve wordlist: a bundled name, an exact file path, or (empty) the
    # bundled default -- same resolution shape as kerbrute_spray.
    resolved_wordlist = resolve_wordlist(wordlist.strip(), fallback=kb_parse.DEFAULT_USERNAMES_WORDLIST)

    argv = build_argv(
        target=host,
        domain=clean_domain,
        wordlist=resolved_wordlist,
        safe=safe,
        binary=binary,
    )

    try:
        proc = run_cmd(
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return kb_parse.RawKerbruteResult(
            target=host, domain=clean_domain, error="kerbrute userenum timed out"
        )
    except Exception as e:
        return kb_parse.RawKerbruteResult(
            target=host, domain=clean_domain, error=f"kerbrute execution failed: {e}"
        )

    users = kb_parse.parse_kerbrute_output(proc.stdout)
    error_msg = None
    if proc.returncode != 0 and not users:
        error_msg = proc.stderr.strip() or f"kerbrute exited with return code {proc.returncode}"

    return kb_parse.RawKerbruteResult(
        target=host,
        domain=clean_domain,
        usernames=users,
        stdout=proc.stdout,
        error=error_msg,
    )
