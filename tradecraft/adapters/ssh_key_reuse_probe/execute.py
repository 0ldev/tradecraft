"""
Subprocess execution for ssh_key_reuse_probe: one SSH private key and one
username, tried against a bounded list of candidate hosts, one
non-interactive key-based authentication attempt per host. No parsing
logic here -- see parse.py.

The supplied PEM content is written to a disposable 0600 temp file for
each attempt (``ssh -i``) and removed in a ``finally`` regardless of
outcome. Each attempt runs ``ssh`` with password auth, agent forwarding
and interactive prompts disabled, so a declined key fails fast instead
of hanging. On success the session runs one fixed confirmation command
(``id``) and its output is captured.

Hard caps, enforced here regardless of the tool layer: at most
MAX_TARGETS candidate targets per call (a longer list is rejected, not
truncated), one attempt per target, no retries.
"""
from __future__ import annotations

import contextlib
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Iterator, List, Optional, Tuple

MAX_TARGETS = 20
DEFAULT_TIMEOUT = 30  # per target, seconds
CONFIRM_COMMAND = "id"

_PEM_BEGIN_RE = re.compile(r"^-----BEGIN ((?:[A-Z0-9]+ )*)PRIVATE KEY-----$")

SSH_OPTIONS: Tuple[str, ...] = (
    "PasswordAuthentication=no",
    "PubkeyAuthentication=yes",
    "StrictHostKeyChecking=no",
    "UserKnownHostsFile=/dev/null",
    "BatchMode=yes",
    "IdentitiesOnly=yes",
    "ForwardAgent=no",
    "ConnectTimeout=10",
)


@dataclass
class RawTargetAttempt:
    target: str = ""
    host: str = ""
    port: Optional[int] = None
    returncode: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    error: Optional[str] = None


@dataclass
class RawKeyReuseResult:
    ssh_user: str = ""
    targets_requested: int = 0
    attempts: List[RawTargetAttempt] = field(default_factory=list)
    error: Optional[str] = None


def find_ssh_binary() -> Optional[str]:
    """Finds the ssh client binary on PATH."""
    return shutil.which("ssh")


def is_private_key_pem(pem: str) -> bool:
    """True when the first non-blank line is a PEM private-key header."""
    for line in (pem or "").splitlines():
        if line.strip():
            return _PEM_BEGIN_RE.match(line.strip()) is not None
    return False


def normalize_pem(pem: str) -> str:
    """Normalizes line endings and guarantees a trailing newline, which
    OpenSSH requires for a private key file to parse."""
    return pem.replace("\r\n", "\n").strip("\n") + "\n"


def parse_target(target: str) -> Tuple[str, Optional[int]]:
    """Splits a ``host`` or ``host:port`` target. Returns ("", None) for
    anything malformed (empty host, non-numeric or out-of-range port)."""
    cleaned = (target or "").strip()
    if not cleaned:
        return "", None
    if ":" in cleaned:
        host, _, port_s = cleaned.rpartition(":")
        host = host.strip()
        if not host or not port_s.strip().isdigit():
            return "", None
        port = int(port_s.strip())
        if not 1 <= port <= 65535:
            return "", None
        return host, port
    return cleaned, None


@contextlib.contextmanager
def private_key_file(pem: str) -> Iterator[str]:
    """Writes the PEM content to a 0600 temp file and removes it on exit,
    whether or not the attempt succeeded."""
    fd, path = tempfile.mkstemp(prefix="rsskr-", suffix=".key")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(pem)
        yield path
    finally:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass


def build_argv(
    host: str,
    port: Optional[int],
    ssh_user: str,
    key_path: str,
    binary: str = "ssh",
) -> List[str]:
    """Builds argv for one non-interactive key-auth ssh run that executes
    the fixed confirmation command in the same session."""
    argv = [binary, "-F", "/dev/null", "-i", key_path]
    for opt in SSH_OPTIONS:
        argv.extend(["-o", opt])
    if port is not None:
        argv.extend(["-p", str(port)])
    argv.append(f"{ssh_user}@{host}")
    argv.append(CONFIRM_COMMAND)
    return argv


def execute(
    private_key: str,
    ssh_user: str,
    targets: List[str],
    timeout: Optional[int] = None,
    runner=None,
) -> RawKeyReuseResult:
    """Tries one SSH key against each target in order, once each."""
    user = (ssh_user or "").strip()
    if not user:
        return RawKeyReuseResult(error="ssh_user is required for ssh_key_reuse_probe")
    if not isinstance(targets, list) or not targets:
        return RawKeyReuseResult(
            ssh_user=user, error="targets must be a non-empty list of host or host:port"
        )
    if len(targets) > MAX_TARGETS:
        return RawKeyReuseResult(
            ssh_user=user,
            targets_requested=len(targets),
            error=(
                f"targets has {len(targets)} entries; the maximum per call is "
                f"{MAX_TARGETS}. Split the list into multiple calls."
            ),
        )
    if not is_private_key_pem(private_key):
        return RawKeyReuseResult(
            ssh_user=user,
            error="private_key must be PEM private key content (BEGIN ... PRIVATE KEY)",
        )

    parsed: List[Tuple[str, str, Optional[int]]] = []
    seen = set()
    for raw_target in targets:
        host, port = parse_target(raw_target if isinstance(raw_target, str) else "")
        if not host:
            return RawKeyReuseResult(
                ssh_user=user,
                targets_requested=len(targets),
                error=f"invalid target {raw_target!r}: expected 'host' or 'host:port'",
            )
        key = (host, port)
        if key in seen:
            continue  # never attempt the same host:port twice
        seen.add(key)
        parsed.append((str(raw_target).strip(), host, port))

    binary = find_ssh_binary()
    if binary is None:
        return RawKeyReuseResult(
            ssh_user=user, targets_requested=len(targets),
            error="ssh binary not found on PATH",
        )

    if timeout is None:
        timeout = DEFAULT_TIMEOUT
    run_cmd = runner or subprocess.run
    pem = normalize_pem(private_key)

    attempts: List[RawTargetAttempt] = []
    for target, host, port in parsed:
        attempt = RawTargetAttempt(target=target, host=host, port=port)
        with private_key_file(pem) as key_path:
            argv = build_argv(host, port, user, key_path, binary=binary)
            try:
                proc = run_cmd(
                    argv,
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )
                attempt.returncode = proc.returncode
                attempt.stdout = proc.stdout or ""
                attempt.stderr = proc.stderr or ""
            except subprocess.TimeoutExpired:
                attempt.error = f"ssh timed out after {timeout}s"
            except FileNotFoundError:
                attempt.error = "ssh binary not found on PATH"
            except Exception as exc:  # noqa: BLE001 - surfaced per target
                attempt.error = f"ssh execution failed: {exc}"
        attempts.append(attempt)

    return RawKeyReuseResult(
        ssh_user=user,
        targets_requested=len(targets),
        attempts=attempts,
    )
