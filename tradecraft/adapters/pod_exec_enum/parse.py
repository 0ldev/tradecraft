"""
Parsing logic for pod_exec_enum: the marker-delimited stdout of the fixed
in-container script built in execute.py, returned over ``kubectl exec``.

Pure functions, no I/O, no subprocess calls.

Output grammar:

    @@PEE:BEGIN sa_token
    token_file <absent|unreadable|present>
    token_size_bytes <n>          (only when token_file is present)
    token_begin
    <raw token body>
    token_end
    namespace_file <absent|unreadable|present>
    namespace_value <value>       (only when namespace_file is present)
    @@PEE:END sa_token
    @@PEE:BEGIN docker_socket
    socket <absent|present>
    writable <yes|no>             (only when socket is present)
    @@PEE:END docker_socket
    @@PEE:BEGIN capabilities
    capeff <hex>                  or  capeff unavailable
    @@PEE:END capabilities
    @@PEE:BEGIN cgroup_release_agent
    cgroup_version <v1|v2>
    <controller>_release_agent <absent|writable|not_writable>   (one line
                                   per entry in CGROUP_CONTROLLERS, only
                                   when cgroup_version is v1)
    @@PEE:END cgroup_release_agent
    @@PEE:DONE

The token is returned in full: it is a legitimate credential a real
engagement would pivot with next, so it is deliberately not redacted.

CapEff is only ever printed raw by the remote script; the bitmask decode
into capability names happens here, in ``decode_capability_mask``.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

BEGIN_PREFIX = "@@PEE:BEGIN"
END_PREFIX = "@@PEE:END"
DONE_MARKER = "@@PEE:DONE"
TOKEN_BEGIN = "@@PEE:TOKEN_BEGIN"
TOKEN_END = "@@PEE:TOKEN_END"

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_BEGIN_RE = re.compile(r"^@@PEE:BEGIN (\S+)$")
_END_RE = re.compile(r"^@@PEE:END (\S+)$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

# Linux capability bit -> name, indexed by bit number. Source:
# linux/capability.h (CAP_LAST_CAP = CAP_CHECKPOINT_RESTORE = 40). Bits
# above the last entry are reported as unknown_bits rather than guessed.
CAPABILITY_NAMES: Tuple[str, ...] = (
    "CAP_CHOWN",               # 0
    "CAP_DAC_OVERRIDE",        # 1
    "CAP_DAC_READ_SEARCH",     # 2
    "CAP_FOWNER",              # 3
    "CAP_FSETID",              # 4
    "CAP_KILL",                # 5
    "CAP_SETGID",              # 6
    "CAP_SETUID",              # 7
    "CAP_SETPCAP",             # 8
    "CAP_LINUX_IMMUTABLE",     # 9
    "CAP_NET_BIND_SERVICE",    # 10
    "CAP_NET_BROADCAST",       # 11
    "CAP_NET_ADMIN",           # 12
    "CAP_NET_RAW",             # 13
    "CAP_IPC_LOCK",            # 14
    "CAP_IPC_OWNER",           # 15
    "CAP_SYS_MODULE",          # 16
    "CAP_SYS_RAWIO",           # 17
    "CAP_SYS_CHROOT",          # 18
    "CAP_SYS_PTRACE",          # 19
    "CAP_SYS_PACCT",           # 20
    "CAP_SYS_ADMIN",           # 21
    "CAP_SYS_BOOT",            # 22
    "CAP_SYS_NICE",            # 23
    "CAP_SYS_RESOURCE",        # 24
    "CAP_SYS_TIME",            # 25
    "CAP_SYS_TTY_CONFIG",      # 26
    "CAP_MKNOD",               # 27
    "CAP_LEASE",               # 28
    "CAP_AUDIT_WRITE",         # 29
    "CAP_AUDIT_CONTROL",       # 30
    "CAP_SETFCAP",             # 31
    "CAP_MAC_OVERRIDE",        # 32
    "CAP_MAC_ADMIN",           # 33
    "CAP_SYSLOG",              # 34
    "CAP_WAKE_ALARM",          # 35
    "CAP_BLOCK_SUSPEND",       # 36
    "CAP_AUDIT_READ",          # 37
    "CAP_PERFMON",             # 38
    "CAP_BPF",                 # 39
    "CAP_CHECKPOINT_RESTORE",  # 40
)


@dataclass
class RawPodExecResult:
    server: str = ""
    namespace: str = ""
    pod: str = ""
    container: str = ""
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    error: Optional[str] = None


def strip_ansi(text: str) -> str:
    """Removes ANSI color escape sequences from terminal output."""
    return _ANSI_RE.sub("", text or "")


def decode_capability_mask(hex_value: str) -> Dict[str, Any]:
    """Decodes a CapEff hex bitmask into capability names.

    Returns ``{"cap_eff_hex", "effective_capabilities", "unknown_bits"}``.
    ``unknown_bits`` lists set bits above the known table (ascending) so a
    newer kernel's capability is reported by number, not dropped.
    Raises ValueError for a value that is not a hex string.
    """
    value = (hex_value or "").strip()
    if not _HEX_RE.match(value):
        raise ValueError(f"not a hex capability mask: {hex_value!r}")
    mask = int(value, 16)
    names = [
        CAPABILITY_NAMES[bit]
        for bit in range(len(CAPABILITY_NAMES))
        if (mask >> bit) & 1
    ]
    unknown = [
        bit
        for bit in range(len(CAPABILITY_NAMES), mask.bit_length())
        if (mask >> bit) & 1
    ]
    return {
        "cap_eff_hex": value,
        "effective_capabilities": names,
        "unknown_bits": unknown,
    }


def _parse_blocks(output: str) -> Tuple[Dict[str, Dict[str, Any]], bool]:
    """Splits the script's stdout into ``{label: {key: value}}``.

    Each body line is ``<key> <value>`` (value may be empty). The lines
    between ``token_begin`` and ``token_end`` are kept verbatim under
    ``token_body``. Returns ``(blocks, complete)``; ``complete`` is True
    only when the DONE marker was seen.
    """
    blocks: Dict[str, Dict[str, Any]] = {}
    current: Optional[Dict[str, Any]] = None
    in_token = False
    token_lines: List[str] = []
    complete = False

    for raw_line in (output or "").splitlines():
        line = raw_line.rstrip("\r")

        if line == DONE_MARKER:
            complete = True
            continue

        begin = _BEGIN_RE.match(line)
        if begin:
            current = {}
            blocks[begin.group(1)] = current
            in_token = False
            token_lines = []
            continue

        end = _END_RE.match(line)
        if end and current is not None:
            current = None
            continue

        if current is None:
            continue

        if in_token:
            if line == TOKEN_END:
                in_token = False
                current["token_body"] = "\n".join(token_lines).strip()
            else:
                token_lines.append(line)
            continue

        if line == TOKEN_BEGIN:
            in_token = True
            token_lines = []
            continue

        key, _, value = line.partition(" ")
        if key:
            current[key] = value.strip()

    return blocks, complete


def _parse_sa_token(block: Dict[str, Any]) -> Dict[str, Any]:
    token_file = block.get("token_file", "absent")
    record: Dict[str, Any] = {"token_file": token_file}
    if token_file == "present":
        size = block.get("token_size_bytes", "")
        record["token_size_bytes"] = int(size) if size.isdigit() else None
        record["token"] = block.get("token_body", "")
        record["token_present"] = True
    else:
        record["token_present"] = False
        if token_file == "unreadable":
            record["note"] = "token file exists but is not readable by the container user"

    ns_file = block.get("namespace_file", "absent")
    record["namespace_file"] = ns_file
    if ns_file == "present":
        record["pod_namespace"] = block.get("namespace_value", "")
    return record


def _parse_docker_socket(block: Dict[str, Any]) -> Dict[str, Any]:
    present = block.get("socket", "absent") == "present"
    record: Dict[str, Any] = {"socket_present": present}
    if present:
        record["writable"] = block.get("writable", "") == "yes"
    return record


def _parse_capabilities(block: Dict[str, Any]) -> Dict[str, Any]:
    capeff = block.get("capeff", "")
    if not capeff or capeff == "unavailable":
        return {"status": "unavailable"}
    try:
        return decode_capability_mask(capeff)
    except ValueError as exc:
        return {"status": "unparseable", "note": str(exc)}


def _parse_cgroup_release_agent(block: Dict[str, Any]) -> Dict[str, Any]:
    """Imported lazily to avoid a circular import with execute.py, which
    already imports this module -- CGROUP_CONTROLLERS is the same fixed
    tuple execute.py builds the remote script from."""
    from tradecraft.adapters.pod_exec_enum.execute import CGROUP_CONTROLLERS

    version = block.get("cgroup_version", "")
    record: Dict[str, Any] = {"cgroup_version": version or "unknown"}
    if version != "v1":
        return record

    controllers: Dict[str, str] = {}
    writable_any = False
    for ctrl in CGROUP_CONTROLLERS:
        status = block.get(f"{ctrl}_release_agent", "absent")
        controllers[ctrl] = status
        if status == "writable":
            writable_any = True
    record["controllers"] = controllers
    record["release_agent_writable"] = writable_any
    return record


def parse_pod_exec_output(output: str) -> Tuple[Dict[str, Any], bool]:
    """Turns the script's stdout into the four per-check records.

    Returns ``(checks, complete)`` where ``checks`` is keyed by
    ``service_account_token``, ``docker_socket``, ``capabilities``, and
    ``cgroup_release_agent``. Checks whose block never appeared are
    absent from the dict.
    """
    blocks, complete = _parse_blocks(strip_ansi(output))
    parsers = {
        "sa_token": ("service_account_token", _parse_sa_token),
        "docker_socket": ("docker_socket", _parse_docker_socket),
        "capabilities": ("capabilities", _parse_capabilities),
        "cgroup_release_agent": ("cgroup_release_agent", _parse_cgroup_release_agent),
    }
    checks: Dict[str, Any] = {}
    for label, (key, parser) in parsers.items():
        if label in blocks:
            checks[key] = parser(blocks[label])
    return checks, complete


def parse_pod_exec_result(raw: RawPodExecResult) -> Dict[str, Any]:
    """Turns a raw pod_exec_enum invocation into the model-facing result."""
    base: Dict[str, Any] = {
        "server": raw.server,
        "namespace": raw.namespace,
        "pod": raw.pod,
        "container": raw.container or None,
    }

    if raw.error:
        return {**base, "status": "failed", "error": raw.error}

    checks, complete = parse_pod_exec_output(raw.stdout)
    if not checks:
        detail = (raw.stderr or "").strip()
        error = (
            f"kubectl exec failed (exit {raw.returncode}): {detail}"
            if raw.returncode != 0
            else "no enumeration output received from pod"
        )
        return {**base, "status": "failed", "error": error}

    return {
        **base,
        "status": "success",
        "complete": complete,
        "checks": checks,
    }
