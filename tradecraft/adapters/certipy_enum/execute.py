"""
Subprocess execution for certipy_enum: read-only AD CS enumeration via
`certipy find`. No parsing logic here -- see parse.py.
"""
from __future__ import annotations

import ipaddress
import os
import re
import shutil
import subprocess
import tempfile
from typing import List, Optional, Tuple

from tradecraft.adapters.certipy_enum import parse as ce_parse

DEFAULT_TIMEOUT = 300
# Per-connection timeout handed to Certipy itself, not the process timeout.
CONNECTION_TIMEOUT = 10

SCHEMES = ("ldap", "ldaps")

# An IPv4 range such as 10.0.0.1-10.0.0.50. Certipy accepts CIDR/list
# targets via the DC hostname, but this tool enumerates one DC.
_IPV4_RANGE_REGEX = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}\s*-\s*\d")


def find_certipy_binary() -> Optional[str]:
    """Finds the certipy binary on PATH."""
    return shutil.which("certipy")


def _validate_target(host: str, raw_target: str = "") -> Optional[str]:
    """Rejects anything that is not a single DC host."""
    if not host:
        return "empty target host"

    candidate = (raw_target or host).strip()
    if "://" not in candidate:
        if os.path.exists(candidate):
            return "invalid target: looks like a local file, not a host"
        if "\\" in candidate:
            return "invalid target: looks like a local path, not a host"
        if "/" in candidate:
            return (
                "certipy_enum runs against a single domain controller "
                "only; CIDR ranges are not accepted"
            )

    if "," in host or any(char.isspace() for char in host):
        return (
            "certipy_enum runs against a single domain controller only; "
            "target lists are not accepted"
        )
    if _IPV4_RANGE_REGEX.match(host):
        return (
            "certipy_enum runs against a single domain controller only; "
            "IP ranges are not accepted"
        )
    return None


def _validate_domain(domain: str) -> Optional[str]:
    clean = (domain or "").strip()
    if not clean:
        return "domain is required for certipy_enum"
    if any(char.isspace() for char in clean):
        return "domain must not contain whitespace"
    if any(char in clean for char in "/\\,@"):
        return "domain must be a bare domain name, e.g. 'corp.local'"
    return None


def _normalize_username(
    username: str, domain: str
) -> Tuple[Optional[str], Optional[str]]:
    """Returns ``(username@domain, error)``.

    Accepts a bare username, a UPN, or ``DOMAIN\\user``. If the supplied
    form carries a domain, it must match the required ``domain`` argument
    case-insensitively -- otherwise the tool would authenticate to a
    different domain than the caller asked for.
    """
    user = (username or "").strip()
    if not user:
        return None, "username is required for certipy_enum"

    if "\\" in user:
        supplied_domain, _, user = user.partition("\\")
        if supplied_domain and supplied_domain.casefold() != domain.casefold():
            return None, (
                f"username domain '{supplied_domain}' does not match "
                f"domain '{domain}'"
            )
    elif "@" in user:
        user, _, supplied_domain = user.partition("@")
        if supplied_domain and supplied_domain.casefold() != domain.casefold():
            return None, (
                f"username domain '{supplied_domain}' does not match "
                f"domain '{domain}'"
            )

    user = user.strip()
    if not user:
        return None, "username is required for certipy_enum"
    return f"{user}@{domain}", None


def _validate_credentials(
    username: str, password: str, hashes: str, domain: str
) -> Optional[str]:
    if not username.strip():
        return "username is required for certipy_enum"
    if password.strip() and hashes.strip():
        return "provide at most one of password or hashes, not both"
    if not password.strip() and not hashes.strip():
        return "one of password or hashes is required for certipy_enum"
    return _validate_domain(domain)


def _validate_dc_ip(dc_ip: str) -> Optional[str]:
    clean = (dc_ip or "").strip()
    if not clean:
        return None
    try:
        ipaddress.ip_address(clean)
    except ValueError:
        return f"dc_ip '{dc_ip}' is not a single IP address"
    return None


def build_argv(
    target: str,
    domain: str,
    username: str,
    password: str = "",
    hashes: str = "",
    dc_ip: str = "",
    scheme: str = "ldaps",
    enabled_only: bool = False,
    vulnerable_only: bool = False,
    hide_admins: bool = False,
    dc_only: bool = False,
    output_prefix: str = "certipy",
    binary: str = "certipy",
) -> List[str]:
    """Builds argv for one bounded `certipy find` enumeration."""
    clean_target = ce_parse.normalize_target_host(target)
    principal, username_error = _normalize_username(username, domain)
    if username_error:
        raise ValueError(username_error)

    argv = [
        binary,
        "find",
        "-json",
        "-output",
        output_prefix,
        "-target",
        clean_target,
        "-u",
        principal,
        "-timeout",
        str(CONNECTION_TIMEOUT),
    ]

    if password.strip():
        argv.extend(["-p", password.strip()])
    elif hashes.strip():
        argv.extend(["-hashes", hashes.strip()])

    if dc_ip.strip():
        argv.extend(["-dc-ip", dc_ip.strip()])
    if scheme.strip():
        argv.extend(["-scheme", scheme.strip().lower()])
    if enabled_only:
        argv.append("-enabled")
    if vulnerable_only:
        argv.append("-vulnerable")
    if hide_admins:
        argv.append("-hide-admins")
    if dc_only:
        argv.append("-dc-only")

    return argv


def output_path_for_prefix(prefix: str) -> str:
    """The exact file Certipy writes for `-json -output <prefix>`."""
    return f"{prefix}_Certipy.json"


def execute(
    target: str,
    domain: str,
    username: str,
    password: str = "",
    hashes: str = "",
    dc_ip: str = "",
    scheme: str = "ldaps",
    enabled_only: bool = False,
    vulnerable_only: bool = False,
    hide_admins: bool = False,
    dc_only: bool = False,
    timeout: Optional[int] = None,
    runner=None,
) -> ce_parse.RawCertipyEnumResult:
    """Executes one read-only `certipy find` enumeration."""
    host = ce_parse.normalize_target_host(target)
    clean_scheme = (scheme or "").strip().lower() or "ldaps"

    target_error = _validate_target(host, target)
    if target_error:
        return ce_parse.RawCertipyEnumResult(
            target=host, domain=domain.strip(), scheme=clean_scheme,
            error=target_error,
        )

    credential_error = _validate_credentials(
        username, password, hashes, domain
    )
    if credential_error:
        return ce_parse.RawCertipyEnumResult(
            target=host, domain=domain.strip(), scheme=clean_scheme,
            error=credential_error,
        )

    _, username_error = _normalize_username(username, domain)
    if username_error:
        return ce_parse.RawCertipyEnumResult(
            target=host, domain=domain.strip(), scheme=clean_scheme,
            error=username_error,
        )

    dc_ip_error = _validate_dc_ip(dc_ip)
    if dc_ip_error:
        return ce_parse.RawCertipyEnumResult(
            target=host, domain=domain.strip(), scheme=clean_scheme,
            error=dc_ip_error,
        )

    if clean_scheme not in SCHEMES:
        return ce_parse.RawCertipyEnumResult(
            target=host,
            domain=domain.strip(),
            scheme=clean_scheme,
            error=(
                f"unsupported scheme '{scheme}'; expected one of "
                f"{', '.join(SCHEMES)}"
            ),
        )

    binary = find_certipy_binary()
    if binary is None:
        return ce_parse.RawCertipyEnumResult(
            target=host,
            domain=domain.strip(),
            scheme=clean_scheme,
            error="certipy binary not found on PATH",
        )

    if timeout is None:
        timeout = DEFAULT_TIMEOUT

    output_dir = tempfile.mkdtemp(prefix="tradecraft_certipy_")
    output_prefix = os.path.join(output_dir, "certipy")
    json_path = output_path_for_prefix(output_prefix)

    argv = build_argv(
        target=host,
        domain=domain,
        username=username,
        password=password,
        hashes=hashes,
        dc_ip=dc_ip,
        scheme=clean_scheme,
        enabled_only=enabled_only,
        vulnerable_only=vulnerable_only,
        hide_admins=hide_admins,
        dc_only=dc_only,
        output_prefix=output_prefix,
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
        json_output = None
        if os.path.exists(json_path):
            with open(json_path, "r", encoding="utf-8", errors="replace") as f:
                json_output = f.read()

        return ce_parse.RawCertipyEnumResult(
            target=host,
            domain=domain.strip(),
            scheme=clean_scheme,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            returncode=proc.returncode,
            json_output=json_output,
        )
    except subprocess.TimeoutExpired:
        return ce_parse.RawCertipyEnumResult(
            target=host,
            domain=domain.strip(),
            scheme=clean_scheme,
            error=f"certipy find timed out after {timeout}s",
        )
    except Exception as e:  # noqa: BLE001 - surfaced to the model as a tool error
        return ce_parse.RawCertipyEnumResult(
            target=host,
            domain=domain.strip(),
            scheme=clean_scheme,
            error=f"certipy execution failed: {e}",
        )
    finally:
        shutil.rmtree(output_dir, ignore_errors=True)
