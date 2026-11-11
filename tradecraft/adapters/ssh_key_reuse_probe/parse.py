"""
Pure parsing for ssh_key_reuse_probe: turns the per-target raw ssh
attempts into per-target records and a summary.

Pure functions, no I/O, no subprocess calls.

Auth-success heuristic: the attempt runs ``ssh`` with BatchMode and no
password fallback, so a declined key or an unreachable host makes ssh
itself exit 255 without ever running the remote command. Any other exit
status means authentication succeeded and the session ran. Output from
the confirmation command is only reported as a shell when it is non-empty
after stripping; a forced command or an immediately-closed session shows
up as auth success with no output.
"""
from __future__ import annotations

from typing import Any, Dict, List

from tradecraft.adapters.linpeas.parse import detect_ssh_error
from tradecraft.adapters.ssh_key_reuse_probe.execute import RawKeyReuseResult, RawTargetAttempt

SSH_AUTH_FAILURE_RC = 255
MAX_OUTPUT_CHARS = 2000


def _short_error(attempt: RawTargetAttempt) -> str:
    """Best short reason for a failed attempt -- never the key material."""
    ssh_error = detect_ssh_error(attempt.stdout, attempt.stderr)
    if ssh_error:
        return ssh_error
    combined = f"{attempt.stdout or ''}\n{attempt.stderr or ''}"
    lines = [ln.strip() for ln in combined.splitlines() if ln.strip()]
    if lines:
        return lines[-1]
    return f"ssh exited {attempt.returncode} without a reason"


def parse_target_result(attempt: RawTargetAttempt) -> Dict[str, Any]:
    record: Dict[str, Any] = {
        "target": attempt.target,
        "host": attempt.host,
        "port": attempt.port,
    }

    if attempt.error:
        record["auth_succeeded"] = False
        record["confirmation_output_present"] = False
        record["error"] = attempt.error
        return record

    if attempt.returncode is None or attempt.returncode == SSH_AUTH_FAILURE_RC:
        record["auth_succeeded"] = False
        record["confirmation_output_present"] = False
        record["error"] = _short_error(attempt)
        return record

    output = (attempt.stdout or "").strip()
    record["auth_succeeded"] = True
    record["confirmation_output_present"] = bool(output)
    if output:
        record["confirmation_output"] = output[:MAX_OUTPUT_CHARS]
        record["confirmation_output_truncated"] = len(output) > MAX_OUTPUT_CHARS
    return record


def parse_key_reuse_result(raw: RawKeyReuseResult) -> Dict[str, Any]:
    """Turns one raw multi-target invocation into the model-facing
    summary plus a per-target results list."""
    if raw.error:
        return {
            "ssh_user": raw.ssh_user,
            "targets_requested": raw.targets_requested,
            "targets_attempted": 0,
            "auth_succeeded_count": 0,
            "confirmed_shell_count": 0,
            "results": [],
            "error": raw.error,
        }

    results: List[Dict[str, Any]] = [parse_target_result(a) for a in raw.attempts]
    auth_succeeded_count = sum(1 for r in results if r.get("auth_succeeded"))
    confirmed_shell_count = sum(1 for r in results if r.get("confirmation_output_present"))

    return {
        "ssh_user": raw.ssh_user,
        "targets_requested": raw.targets_requested,
        "targets_attempted": len(results),
        "auth_succeeded_count": auth_succeeded_count,
        "confirmed_shell_count": confirmed_shell_count,
        "results": results,
    }
