"""
Subprocess execution for kube_hunter_enum: passive remote kube-hunter
scanning. No parsing logic here -- see parse.py.

Never passes ``--active``: kube-hunter only registers ActiveHunter hooks
when that flag is set (``core/events/event_handler.py``), so omitting it
keeps every exploitation/mutation-shaped check out of the run.
"""
from __future__ import annotations

import shutil
import subprocess
from typing import List, Optional

from tradecraft.adapters.kube_hunter_enum import parse as kh_parse

DEFAULT_TIMEOUT = 600
# kube-hunter's default is 800 worker threads; a /24 can otherwise turn
# into a very loud scan.
NUM_WORKER_THREADS = 32
NETWORK_TIMEOUT = 3


def find_kube_hunter_binary() -> Optional[str]:
    """Finds the kube-hunter binary on PATH."""
    return shutil.which("kube-hunter")


def build_argv(
    target: str,
    token: str = "",
    cve_hunting: bool = False,
    binary: str = "kube-hunter",
) -> List[str]:
    """Builds argv for one bounded passive kube-hunter scan."""
    kind, value, error = kh_parse.parse_target(target)
    if error:
        raise ValueError(error)

    argv = [binary]
    if kind == "cidr":
        argv.extend(["--cidr", value])
    else:
        argv.extend(["--remote", value])

    argv.extend(
        [
            "--report",
            "json",
            "--dispatch",
            "stdout",
            "--log",
            "none",
            "--network-timeout",
            str(NETWORK_TIMEOUT),
            "--num-worker-threads",
            str(NUM_WORKER_THREADS),
        ]
    )

    if token.strip():
        argv.extend(["--service-account-token", token.strip()])
    if cve_hunting:
        argv.append("--enable-cve-hunting")

    return argv


def execute(
    target: str,
    token: str = "",
    cve_hunting: bool = False,
    timeout: Optional[int] = None,
    runner=None,
) -> kh_parse.RawKubeHunterResult:
    """Executes one passive kube-hunter scan."""
    kind, value, target_error = kh_parse.parse_target(target)
    if target_error:
        return kh_parse.RawKubeHunterResult(
            target=(target or "").strip(),
            target_kind=kind,
            error=target_error,
        )

    binary = find_kube_hunter_binary()
    if binary is None:
        return kh_parse.RawKubeHunterResult(
            target=value,
            target_kind=kind,
            error="kube-hunter binary not found on PATH",
        )

    if timeout is None:
        timeout = DEFAULT_TIMEOUT

    argv = build_argv(
        target=value,
        token=token,
        cve_hunting=cve_hunting,
        binary=binary,
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
        return kh_parse.RawKubeHunterResult(
            target=value,
            target_kind=kind,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            returncode=proc.returncode,
        )
    except subprocess.TimeoutExpired:
        return kh_parse.RawKubeHunterResult(
            target=value,
            target_kind=kind,
            error=f"kube-hunter timed out after {timeout}s",
        )
    except Exception as exc:  # noqa: BLE001 - surfaced to the model as a tool error
        return kh_parse.RawKubeHunterResult(
            target=value,
            target_kind=kind,
            error=f"kube-hunter execution failed: {exc}",
        )
