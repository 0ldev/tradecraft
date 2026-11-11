"""
Subprocess execution for powerview: Active Directory domain and object enumeration.
No parsing logic here -- see parse.py.
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

from tradecraft.adapters.powerview import parse as pv_parse

DEFAULT_TIMEOUT = 120


def find_powerview_binary() -> Optional[str]:
    """Finds powerview binary on PATH."""
    return shutil.which("powerview")


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def build_argv(
    target: str,
    domain: str,
    username: str = "",
    password: str = "",
    hashes: str = "",
    query: str = "Get-DomainUser",
    use_ldap: bool = False,
    kerberos: bool = False,
    binary: str = "powerview",
) -> List[str]:
    """
    Builds argv for `powerview` invocation.
    Target format in powerview is:
      [[domain/]username[:password]@]<targetName or address>
    """
    clean_domain = domain.strip()
    clean_user = username.strip()
    clean_pass = password.strip()
    clean_hashes = hashes.strip()
    clean_query = query.strip() if query and query.strip() else "Get-DomainUser"

    if clean_user:
        if clean_pass:
            conn_target = f"{clean_domain}/{clean_user}:{clean_pass}@{target}"
        else:
            conn_target = f"{clean_domain}/{clean_user}@{target}"
    else:
        conn_target = target

    argv = [
        binary,
        conn_target,
        "--dc-ip",
        target,
        "-q",
        clean_query,
        "--no-cache",
        "--no-admin-check",
    ]

    # If no password, no hash, and not kerberos, pass --no-pass to prevent prompt on stdin
    if not clean_pass and not clean_hashes and not kerberos:
        argv.append("--no-pass")

    if clean_hashes:
        argv.extend(["-H", clean_hashes])

    if kerberos:
        argv.append("-k")

    if use_ldap:
        argv.append("--use-ldap")

    return argv


def execute(
    target: str,
    domain: str,
    username: str = "",
    password: str = "",
    hashes: str = "",
    query: str = "Get-DomainUser",
    use_ldap: bool = False,
    kerberos: bool = False,
    ccache_b64: str = "",
    timeout: int = DEFAULT_TIMEOUT,
    runner=None,
) -> pv_parse.RawPowerViewResult:
    """Executes powerview query against the target Domain Controller.

    ccache_b64 (e.g. ticketer's forged ticket) is materialized into a
    disposable KRB5CCNAME file for this one call only, and only takes
    effect with kerberos=True -- powerview's own -k flag ("Use Kerberos
    authentication. Grabs credentials from .ccache file (KRB5CCNAME)
    based on target parameters") is what makes it read KRB5CCNAME at
    all; setting the env var without -k would do nothing.
    """
    host = pv_parse.normalize_target_host(target)
    if not host:
        return pv_parse.RawPowerViewResult(error="empty target domain controller host")
    if not domain or not domain.strip():
        return pv_parse.RawPowerViewResult(target=host, error="missing required Active Directory domain")

    if kerberos and _is_ip_address(host):
        # Kerberos auth fails with "Kerberos authentication requires FQDN
        # instead of IP" when the connection target is a bare IP --
        # Kerberos service tickets are bound to a hostname (SPN), not an
        # address, so this isn't a powerview quirk to work around, it's
        # inherent to Kerberos.
        return pv_parse.RawPowerViewResult(
            target=host, domain=domain.strip(), query=query,
            error="kerberos=true requires target to be a hostname/FQDN, not a bare IP address",
        )

    clean_ccache_b64 = (ccache_b64 or "").strip()
    if clean_ccache_b64 and not kerberos:
        return pv_parse.RawPowerViewResult(
            target=host, domain=domain.strip(), query=query,
            error="ccache_b64 requires kerberos=true",
        )
    ccache_bytes: Optional[bytes] = None
    if clean_ccache_b64:
        try:
            ccache_bytes = base64.b64decode(clean_ccache_b64, validate=True)
        except (binascii.Error, ValueError):
            return pv_parse.RawPowerViewResult(
                target=host, domain=domain.strip(), query=query,
                error="ccache_b64 is not valid base64",
            )

    binary = find_powerview_binary()
    if binary is None:
        return pv_parse.RawPowerViewResult(
            target=host,
            domain=domain.strip(),
            query=query,
            error="powerview binary not found on PATH",
        )

    clean_domain = domain.strip()
    clean_query = query.strip() if query and query.strip() else "Get-DomainUser"
    run_cmd = runner or subprocess.run

    argv = build_argv(
        target=host,
        domain=clean_domain,
        username=username,
        password=password,
        hashes=hashes,
        query=clean_query,
        use_ldap=use_ldap,
        kerberos=kerberos,
        binary=binary,
    )

    ccache_dir = tempfile.mkdtemp(prefix="powerview_kcache_") if ccache_bytes is not None else None
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
        return pv_parse.RawPowerViewResult(
            target=host,
            domain=clean_domain,
            query=clean_query,
            error="powerview execution timed out",
        )
    except Exception as e:
        return pv_parse.RawPowerViewResult(
            target=host,
            domain=clean_domain,
            query=clean_query,
            error=f"powerview execution failed: {e}",
        )
    finally:
        if ccache_dir is not None:
            shutil.rmtree(ccache_dir, ignore_errors=True)

    return pv_parse.RawPowerViewResult(
        target=host,
        domain=clean_domain,
        query=clean_query,
        stdout=proc.stdout or "",
        stderr=proc.stderr or "",
        returncode=proc.returncode,
    )
