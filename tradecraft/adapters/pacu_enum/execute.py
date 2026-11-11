"""
Subprocess execution for pacu_enum: drives the real `pacu` CLI
non-interactively inside a disposable HOME directory so its session
database -- which can echo credential material into its own files --
never persists past one call.

Real pacu 1.7.0 CLI, confirmed against its own `--help` on CT 115:
`pacu [-q] --new-session <name> --set-keys <alias,ak,sk[,token]>
--module-name <module> --module-args=<...> --exec`. `--module-args`
values must use the `=`-joined form (`--module-args=--names-only`),
never a space-separated one -- argparse treats a bare `--names-only`
as a new top-level option otherwise (confirmed against the real CLI
parser; this is also `--module-args`'s own documented example form).

`iam__privesc_scan --scan-only` needs `iam__enum_permissions` to have
already populated the session's confirmed-permissions field, or it
hits a bare `input()` prompt with no corresponding session field --
confirmed empirically as a real `EOFError: EOF when reading a line`
under `stdin=DEVNULL` on CT 115. This adapter always runs
`iam__enum_permissions` first as a prerequisite before `privesc_scan`.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import List

from tradecraft.adapters.pacu_enum.parse import RawPacuEnumResult

PACU_BIN = "pacu"
TIMEOUT_SECONDS = 300


def is_available() -> bool:
    return shutil.which(PACU_BIN) is not None


def _run_pacu(args: List[str], home: str) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["HOME"] = home
    return subprocess.run(
        [PACU_BIN, "-q"] + args,
        text=True,
        capture_output=True,
        timeout=TIMEOUT_SECONDS,
        stdin=subprocess.DEVNULL,
        env=env,
    )


def _names_file(home: str, session: str) -> Path:
    return (
        Path(home) / ".local" / "share" / "pacu" / session / "downloads"
        / "s3__download_bucket" / "s3__download_bucket_file_names.txt"
    )


def execute(target: str, action: str, credential: str) -> RawPacuEnumResult:
    """Runs one of pacu_enum's three read-only actions against `target`
    using `credential` ("AccessKeyId:SecretAccessKey[:SessionToken]").
    `action` is one of "enum_permissions", "privesc_scan", "s3_list".
    """
    session = f"tradecraft_{uuid.uuid4().hex[:10]}"

    creds = [c.strip() for c in (credential or "").split(":")]
    if len(creds) < 2 or not creds[0] or not creds[1]:
        return RawPacuEnumResult(
            target=target, action=action, session=session,
            error="credential must be 'AccessKeyId:SecretAccessKey[:SessionToken]'",
        )
    set_keys_arg = f"tradecraft_key,{creds[0]},{creds[1]}"
    if len(creds) > 2 and creds[2]:
        set_keys_arg += f",{creds[2]}"

    if action not in ("enum_permissions", "privesc_scan", "s3_list"):
        return RawPacuEnumResult(
            target=target, action=action, session=session,
            error=f"unsupported pacu_enum action '{action}'",
        )

    with tempfile.TemporaryDirectory(prefix="pacu_enum_home_") as home:
        try:
            if action == "enum_permissions":
                proc = _run_pacu(
                    [
                        "--new-session", session,
                        "--set-keys", set_keys_arg,
                        "--module-name", "iam__enum_permissions",
                        "--exec",
                    ],
                    home,
                )
                return RawPacuEnumResult(
                    target=target, action=action, session=session,
                    stdout=proc.stdout, stderr=proc.stderr,
                    returncode=proc.returncode,
                )

            if action == "privesc_scan":
                prereq = _run_pacu(
                    [
                        "--new-session", session,
                        "--set-keys", set_keys_arg,
                        "--module-name", "iam__enum_permissions",
                        "--exec",
                    ],
                    home,
                )
                if prereq.returncode != 0:
                    return RawPacuEnumResult(
                        target=target, action=action, session=session,
                        stdout=prereq.stdout, stderr=prereq.stderr,
                        returncode=prereq.returncode,
                    )
                proc = _run_pacu(
                    [
                        "--session", session,
                        "--module-name", "iam__privesc_scan",
                        "--module-args=--scan-only",
                        "--exec",
                    ],
                    home,
                )
                return RawPacuEnumResult(
                    target=target, action=action, session=session,
                    stdout=proc.stdout, stderr=proc.stderr,
                    returncode=proc.returncode,
                )

            proc = _run_pacu(
                [
                    "--new-session", session,
                    "--set-keys", set_keys_arg,
                    "--module-name", "s3__download_bucket",
                    "--module-args=--names-only",
                    "--exec",
                ],
                home,
            )
            names_text = ""
            names_path = _names_file(home, session)
            if names_path.exists():
                names_text = names_path.read_text(errors="ignore")
            return RawPacuEnumResult(
                target=target, action=action, session=session,
                stdout=proc.stdout, stderr=proc.stderr,
                returncode=proc.returncode, names_text=names_text,
            )
        except FileNotFoundError:
            return RawPacuEnumResult(
                target=target, action=action, session=session,
                error="pacu executable not found on PATH",
            )
        except subprocess.TimeoutExpired:
            return RawPacuEnumResult(
                target=target, action=action, session=session,
                error=f"pacu timed out after {TIMEOUT_SECONDS}s",
            )
