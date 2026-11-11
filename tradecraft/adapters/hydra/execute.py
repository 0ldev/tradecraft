"""
Raw execution: builds the hydra argv, bounds wordlist sizes, runs hydra subprocess.
No parsing here -- see parse.py.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Optional

from tradecraft.adapters.hydra import parse as hydra_parse


@dataclass
class RawHydraResult:
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    service: str = ""
    attempts_run: int = 0
    error: Optional[str] = None


def build_argv(
    host: str,
    service: str,
    user_file: str,
    pass_file: str,
    port: Optional[int] = None,
    form_details: str = "",
    tasks: int = 4,
) -> list[str]:
    cmd = ["hydra", "-t", str(tasks), "-I", "-L", user_file, "-P", pass_file]

    if port:
        cmd.extend(["-s", str(port)])

    if "http" in service.lower() and form_details:
        cmd.extend([host, service.lower(), form_details])
    else:
        cmd.append(f"{service}://{host}")

    return cmd


def execute(
    target: str,
    service: str = "",
    username: str = "",
    password_list: str = "",
    form_details: str = "",
    max_attempts: int = 50,
    timeout: int = 180,
    tasks: int = 4,
) -> RawHydraResult:
    target = target.strip()
    if not target:
        return RawHydraResult(error="Target cannot be empty")

    binary = shutil.which("hydra")
    if not binary:
        return RawHydraResult(error="hydra executable not found on PATH")

    host, port = hydra_parse.parse_target_host_port(target)
    normalized_service = hydra_parse.normalize_service(service, target)

    users, passwords = hydra_parse.bound_credential_lists(
        username_input=username,
        password_input=password_list,
        max_attempts=max_attempts,
    )
    attempts_run = len(users) * len(passwords)

    user_tmp = None
    pass_tmp = None

    try:
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix="_users.txt") as u_f:
            u_f.write("\n".join(users) + "\n")
            user_tmp = u_f.name

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix="_pass.txt") as p_f:
            p_f.write("\n".join(passwords) + "\n")
            pass_tmp = p_f.name

        argv = build_argv(
            host=host,
            service=normalized_service,
            user_file=user_tmp,
            pass_file=pass_tmp,
            port=port,
            form_details=form_details,
            tasks=tasks,
        )

        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )

        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        # Hydra validates its own module/argument syntax (service name,
        # -s port, the form_details spec) before attacking anything. On
        # that kind of failure it exits non-zero with an "[ERROR]" line
        # and never sends a single credential attempt -- attempts_run
        # must say 0, not the bounded cap, or a caller reading this
        # result has no way to tell "tried everything, found nothing"
        # apart from "never actually ran."
        ran_attempts = 0 if (proc.returncode != 0 and "[ERROR]" in stderr) else attempts_run

        return RawHydraResult(
            stdout=stdout,
            stderr=stderr,
            returncode=proc.returncode,
            service=normalized_service,
            attempts_run=ran_attempts,
        )
    except FileNotFoundError:
        return RawHydraResult(error="hydra executable not found on PATH", attempts_run=attempts_run)
    except subprocess.TimeoutExpired:
        return RawHydraResult(error=f"hydra timed out after {timeout}s", attempts_run=attempts_run)
    except Exception as exc:
        return RawHydraResult(error=f"hydra execution failed: {str(exc)}", attempts_run=attempts_run)
    finally:
        if user_tmp and os.path.exists(user_tmp):
            try:
                os.remove(user_tmp)
            except OSError:
                pass
        if pass_tmp and os.path.exists(pass_tmp):
            try:
                os.remove(pass_tmp)
            except OSError:
                pass
