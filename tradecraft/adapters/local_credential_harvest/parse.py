"""
Parsing logic for local_credential_harvest: the marker-delimited output
of the fixed remote script built in execute.py, over SSH.

Pure functions, no I/O, no subprocess calls.

Output grammar (one block per path in execute.CREDENTIAL_FILES):

    @@RSCH:BEGIN <label> <presence> <size_bytes> <kind> <path>
    ...body lines, kind-dependent...
    @@RSCH:END <label>
    ...
    @@RSCH:DONE

Where <presence> is one of ``absent``, ``unreadable``, ``present``, or
``not_key_material`` (a private_key-kind path that exists but whose first
line is not a PEM private-key header). The body is only ever what the
remote script decided to print for that kind:

- ``text``: the file's content, capped at MAX_TEXT_BYTES remotely.
- ``private_key``: at most one line -- the PEM/OpenSSH header. The
  parser validates it against PEM_HEADER_RE and discards any additional
  lines, so key body material is never returned to the model even if
  the remote side printed more than the header.
- ``history``: only lines matching the remote credential-pattern grep,
  capped at MAX_HISTORY_LINES remotely.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

BEGIN_PREFIX = "@@RSCH:BEGIN"
END_PREFIX = "@@RSCH:END"
DONE_MARKER = "@@RSCH:DONE"

MAX_TEXT_BYTES = 65_536
MAX_HISTORY_LINES = 200

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_BEGIN_RE = re.compile(r"^@@RSCH:BEGIN (\S+) (\S+) (\d+) (\S+) (\S+)$")
_END_RE = re.compile(r"^@@RSCH:END (\S+)$")

# -----BEGIN RSA PRIVATE KEY----- / -----BEGIN OPENSSH PRIVATE KEY----- /
# -----BEGIN EC PRIVATE KEY----- / -----BEGIN PRIVATE KEY----- (PKCS#8).
PEM_HEADER_RE = re.compile(r"^-----BEGIN ((?:[A-Z0-9]+ )*)PRIVATE KEY-----$")

# A failed ssh/sshpass connection or authentication attempt never produces
# harvest output -- without this check, an unreachable or wrong-credential
# host would be misreported as a clean 0-file result.
_SSH_ERROR_INDICATORS = (
    "permission denied",
    "connection refused",
    "could not resolve hostname",
    "no route to host",
    "connection timed out",
    "host key verification failed",
)


@dataclass
class RawHarvestResult:
    target: str = ""
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    error: Optional[str] = None


def strip_ansi(text: str) -> str:
    """Removes ANSI color escape sequences from terminal output."""
    return _ANSI_RE.sub("", text or "")


def parse_host_port(target: str) -> Tuple[str, Optional[int]]:
    """Splits a ``host`` or ``host:port`` SSH target.

    A port is only returned when the target carries an explicit
    ``:<digits>`` suffix; anything else is passed through untouched.
    """
    cleaned = (target or "").strip()
    if not cleaned:
        return "", None
    if ":" in cleaned:
        parts = cleaned.split(":")
        if len(parts) == 2 and parts[1].strip().isdigit():
            return parts[0].strip(), int(parts[1].strip())
    return cleaned, None


def detect_ssh_error(stdout: str, stderr: str) -> Optional[str]:
    """Detects an ssh/sshpass connection or authentication failure."""
    combined = f"{stdout or ''}\n{stderr or ''}"
    lowered = combined.lower()
    for indicator in _SSH_ERROR_INDICATORS:
        if indicator in lowered:
            for line in combined.splitlines():
                if indicator in line.lower():
                    return line.strip()
            return f"ssh error detected: {indicator}"
    return None


def _finalize_block(
    head: Dict[str, Any], body: List[str]
) -> Dict[str, Any]:
    """Turns one BEGIN..END block into the model-facing per-file record."""
    presence_raw = head["presence_raw"]
    kind = head["kind"]
    record: Dict[str, Any] = {
        "label": head["label"],
        "path": head["path"],
        "kind": kind,
        "size_bytes": head["size_bytes"],
    }

    if presence_raw == "absent":
        record["presence"] = "absent"
        return record
    if presence_raw == "unreadable":
        record["presence"] = "unreadable"
        record["note"] = "file exists but is not readable by the login user"
        return record

    record["presence"] = "present"

    if kind == "private_key":
        if presence_raw == "present" and body:
            m = PEM_HEADER_RE.match(body[0].strip())
            if m:
                key_type = (m.group(1) or "").strip() or "PRIVATE KEY"
                record["looks_like_key"] = True
                record["key_type"] = key_type
                record["key_material"] = "redacted"
                return record
        record["looks_like_key"] = False
        record["note"] = "file present but its first line is not PEM private-key material"
        return record

    if kind == "history":
        lines = [ln for ln in body if ln.strip()]
        record["match_count"] = len(lines)
        record["matching_lines"] = lines[:MAX_HISTORY_LINES]
        record["matching_lines_truncated"] = len(lines) > MAX_HISTORY_LINES
        return record

    # text
    content = "\n".join(body).rstrip("\n")
    record["empty"] = head["size_bytes"] == 0 or content == ""
    record["content"] = content
    record["truncated"] = head["size_bytes"] > MAX_TEXT_BYTES
    return record


def parse_harvest_output(output: str) -> Tuple[List[Dict[str, Any]], bool]:
    """Splits the remote script's stdout into per-file records.

    Returns ``(files, complete)``. ``complete`` is True only when the
    trailing DONE marker was seen -- a dropped connection mid-run leaves
    it False so the caller can say the picture is partial.
    """
    files: List[Dict[str, Any]] = []
    current_head: Optional[Dict[str, Any]] = None
    current_body: List[str] = []
    complete = False

    for raw_line in (output or "").splitlines():
        line = raw_line.rstrip("\r")

        if line == DONE_MARKER:
            complete = True
            continue

        begin = _BEGIN_RE.match(line)
        if begin:
            label, presence_raw, size, kind, path = begin.groups()
            current_head = {
                "label": label,
                "presence_raw": presence_raw,
                "size_bytes": int(size),
                "kind": kind,
                "path": path,
            }
            current_body = []
            continue

        end = _END_RE.match(line)
        if end and current_head is not None:
            files.append(_finalize_block(current_head, current_body))
            current_head = None
            current_body = []
            continue

        if current_head is not None:
            current_body.append(line)

    return files, complete


def parse_harvest_result(raw: RawHarvestResult) -> Dict[str, Any]:
    """Turns a raw credential-harvest invocation into the model-facing
    result."""
    base: Dict[str, Any] = {"target": raw.target}

    if raw.error:
        return {**base, "status": "failed", "error": raw.error}

    files, complete = parse_harvest_output(strip_ansi(raw.stdout))

    if not files:
        ssh_error = detect_ssh_error(raw.stdout, raw.stderr)
        error = ssh_error or "no harvest output received from remote host"
        return {**base, "status": "failed", "error": error}

    present = [f for f in files if f["presence"] == "present"]
    return {
        **base,
        "status": "success",
        "complete": complete,
        "files_checked": len(files),
        "files_present": len(present),
        "private_keys_found": sum(1 for f in files if f.get("looks_like_key")),
        "files": files,
    }

