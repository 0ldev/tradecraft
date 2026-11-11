"""
Subprocess execution for netexec_enum: network service and domain
enumeration. No parsing logic here -- see parse.py.
"""
from __future__ import annotations

import base64
import binascii
import ipaddress
import os
import shutil
import subprocess
import tempfile
from typing import List, Optional

from tradecraft.adapters.netexec_enum import parse as nxe_parse

DEFAULT_TIMEOUT = 180
DEFAULT_PROTOCOL = "smb"

# The protocols this contract exposes (NetExec also ships nfs/vnc, but
# nothing here advertises them until they're covered by tests).
SUPPORTED_PROTOCOLS = (
    "smb",
    "ldap",
    "winrm",
    "mssql",
    "rdp",
    "ssh",
    "ftp",
    "wmi",
)

# NetExec defaults to 256 concurrent threads. A /24 is 256 hosts, so the
# default is a burst against every host at once -- cap it to a gentler
# fixed value, the same per-adapter blast-radius bound every other adapter
# in this project applies.
THREADS = 16

# Refuse a target range broader than a /24. NetExec accepts any CIDR, so a
# typo like 10.0.0.0/8 would otherwise launch 16 million SMB probes from
# one tool call. Narrowing the range is cheap; the operator can pass it
# explicitly.
MAX_CIDR_PREFIX = 24


def find_netexec_binary() -> Optional[str]:
    """Finds the netexec binary on PATH (the project also ships an 'nxc'
    alias -- accept either)."""
    return shutil.which("netexec") or shutil.which("nxc")


def _validate_cidr(host: str) -> Optional[str]:
    """Rejects CIDR ranges broader than /24. Non-CIDR targets pass."""
    if "/" not in host:
        return None
    try:
        network = ipaddress.ip_network(host, strict=False)
    except ValueError:
        return None
    if network.prefixlen < MAX_CIDR_PREFIX:
        return (
            f"target range {host} is broader than /{MAX_CIDR_PREFIX}; "
            "narrow it to a smaller range before enumerating"
        )
    return None


def _validate_protocol(protocol: str) -> Optional[str]:
    clean = (protocol or "").strip().lower()
    if clean not in SUPPORTED_PROTOCOLS:
        return (
            f"unsupported protocol '{protocol}'; expected one of "
            f"{', '.join(SUPPORTED_PROTOCOLS)}"
        )
    return None


def build_argv(
    target: str,
    protocol: str = DEFAULT_PROTOCOL,
    domain: str = "",
    username: str = "",
    password: str = "",
    hashes: str = "",
    shares: bool = False,
    users: bool = False,
    groups: bool = False,
    pass_pol: bool = False,
    disks: bool = False,
    loggedon_users: bool = False,
    use_kcache: bool = False,
    binary: str = "netexec",
) -> List[str]:
    """Builds argv for a NetExec enumeration invocation.

    Anonymous access passes genuinely empty ``-u``/``-p`` arguments
    (NetExec treats those as a null session); the literal two-character
    string ``''`` would instead be sent as a username.

    use_kcache appends --use-kcache -- "Use Kerberos authentication from
    ccache file (KRB5CCNAME)", distinct from the generic -k/--kerberos
    flag. When set, the password/hashes fallback is skipped: an empty -p
    would otherwise still be sent alongside a ccache-based ticket, which
    is not what a ccache-auth call means.
    """
    clean_target = nxe_parse.normalize_target_host(target)
    clean_proto = (protocol or DEFAULT_PROTOCOL).strip().lower()

    argv = [
        binary,
        clean_proto,
        clean_target,
        "-t",
        str(THREADS),
        "--no-progress",
    ]

    if domain.strip():
        argv.extend(["-d", domain.strip()])

    if username.strip():
        argv.extend(["-u", username.strip()])
    else:
        argv.extend(["-u", ""])

    if password.strip():
        argv.extend(["-p", password.strip()])
    elif hashes.strip():
        argv.extend(["-H", hashes.strip()])
    elif not use_kcache:
        argv.extend(["-p", ""])

    if use_kcache:
        argv.append("--use-kcache")

    if shares:
        argv.append("--shares")
    if users:
        argv.append("--users")
    if groups:
        argv.append("--groups")
    if pass_pol:
        argv.append("--pass-pol")
    if disks:
        argv.append("--disks")
    if loggedon_users:
        argv.append("--loggedon-users")

    return argv


def execute(
    target: str,
    protocol: str = DEFAULT_PROTOCOL,
    domain: str = "",
    username: str = "",
    password: str = "",
    hashes: str = "",
    shares: bool = False,
    users: bool = False,
    groups: bool = False,
    pass_pol: bool = False,
    disks: bool = False,
    loggedon_users: bool = False,
    ccache_b64: str = "",
    timeout: int = DEFAULT_TIMEOUT,
    runner=None,
) -> nxe_parse.RawNetexecEnumResult:
    """Executes one NetExec enumeration probe.

    ccache_b64 (e.g. ticketer's forged ticket) is materialized into a
    disposable KRB5CCNAME file for this one call only, and maps to
    NetExec's own --use-kcache flag (not the generic -k/--kerberos flag --
    --use-kcache is the one that actually reads KRB5CCNAME).
    """
    host = nxe_parse.normalize_target_host(target)
    if not host:
        return nxe_parse.RawNetexecEnumResult(error="empty target host")

    protocol_error = _validate_protocol(protocol)
    if protocol_error:
        return nxe_parse.RawNetexecEnumResult(
            target=host, protocol=protocol, error=protocol_error
        )

    range_error = _validate_cidr(host)
    if range_error:
        return nxe_parse.RawNetexecEnumResult(
            target=host, protocol=protocol, error=range_error
        )

    clean_ccache_b64 = (ccache_b64 or "").strip()
    if clean_ccache_b64 and (password.strip() or hashes.strip()):
        return nxe_parse.RawNetexecEnumResult(
            target=host, protocol=protocol,
            error="ccache_b64 is mutually exclusive with password and hashes",
        )
    ccache_bytes: Optional[bytes] = None
    if clean_ccache_b64:
        try:
            ccache_bytes = base64.b64decode(clean_ccache_b64, validate=True)
        except (binascii.Error, ValueError):
            return nxe_parse.RawNetexecEnumResult(
                target=host, protocol=protocol,
                error="ccache_b64 is not valid base64",
            )

    if password.strip() and hashes.strip():
        return nxe_parse.RawNetexecEnumResult(
            target=host,
            protocol=protocol,
            error="provide at most one of password or hashes, not both",
        )

    binary = find_netexec_binary()
    if binary is None:
        return nxe_parse.RawNetexecEnumResult(
            target=host,
            protocol=protocol,
            error="netexec binary not found on PATH",
        )

    run_cmd = runner or subprocess.run
    clean_protocol = protocol.strip().lower()

    argv = build_argv(
        target=host,
        protocol=clean_protocol,
        domain=domain,
        username=username,
        password=password,
        hashes=hashes,
        shares=shares,
        users=users,
        groups=groups,
        pass_pol=pass_pol,
        disks=disks,
        loggedon_users=loggedon_users,
        use_kcache=ccache_bytes is not None,
        binary=binary,
    )

    ccache_dir = tempfile.mkdtemp(prefix="netexec_kcache_") if ccache_bytes is not None else None
    try:
        env = None
        if ccache_bytes is not None:
            # Materializing the ccache file (open/write/chmod) must stay
            # inside this same except-covered try: an I/O error here
            # (disk full, permission error) must return as a normal error
            # result rather than propagate uncaught and crash the
            # tool-calling loop.
            ccache_path = os.path.join(ccache_dir, "ticket.ccache")
            with open(ccache_path, "wb") as handle:
                handle.write(ccache_bytes)
            os.chmod(ccache_path, 0o600)
            env = dict(os.environ)
            env["KRB5CCNAME"] = ccache_path

        proc = run_cmd(
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return nxe_parse.RawNetexecEnumResult(
            target=host,
            protocol=clean_protocol,
            error=f"netexec enumeration timed out after {timeout}s",
        )
    except Exception as e:  # noqa: BLE001 - surfaced to the model as a tool error
        return nxe_parse.RawNetexecEnumResult(
            target=host,
            protocol=clean_protocol,
            error=f"netexec execution failed: {e}",
        )
    finally:
        if ccache_dir is not None:
            shutil.rmtree(ccache_dir, ignore_errors=True)

    return nxe_parse.RawNetexecEnumResult(
        target=host,
        protocol=clean_protocol,
        stdout=proc.stdout or "",
        stderr=proc.stderr or "",
        returncode=proc.returncode,
    )
