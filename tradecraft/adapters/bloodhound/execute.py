"""
Subprocess execution for bloodhound: Active Directory graph data collection.
No parsing logic here -- see parse.py.
"""
from __future__ import annotations

import base64
import binascii
import glob
import os
import shutil
import subprocess
import tempfile
from typing import Dict, List, Optional

from tradecraft.adapters.bloodhound import parse as bh_parse

DEFAULT_TIMEOUT = 180


def find_bloodhound_binary() -> Optional[str]:
    """Finds bloodhound-python or bloodhound binary on PATH."""
    return shutil.which("bloodhound-python") or shutil.which("bloodhound")


def _is_ip_address(host: str) -> bool:
    """Checks if a string looks like an IPv4 or IPv6 address."""
    clean = host.strip()
    if clean.count(".") == 3:
        parts = clean.split(".")
        return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
    return ":" in clean


def build_argv(
    target: str,
    domain: str,
    username: str = "",
    password: str = "",
    hashes: str = "",
    collection_method: str = "DCOnly",
    nameserver: str = "",
    use_ldaps: bool = False,
    kerberos: bool = False,
    prefix: str = "bloodhound_run",
    binary: str = "bloodhound-python",
) -> List[str]:
    """Builds argv for `bloodhound-python` invocation."""
    clean_domain = domain.strip()
    clean_user = username.strip()
    clean_pass = password.strip()
    clean_hashes = hashes.strip()
    clean_method = collection_method.strip() if collection_method and collection_method.strip() else "DCOnly"

    argv = [
        binary,
        "-d",
        clean_domain,
        "-dc",
        target,
        "-c",
        clean_method,
        "-op",
        prefix,
    ]

    if clean_user:
        argv.extend(["-u", clean_user])
    if clean_pass:
        argv.extend(["-p", clean_pass])
    elif clean_hashes:
        argv.extend(["--hashes", clean_hashes])
    elif kerberos:
        argv.append("-k")
    else:
        argv.append("-no-pass")

    clean_ns = nameserver.strip() if nameserver and nameserver.strip() else ""
    if clean_ns:
        argv.extend(["-ns", clean_ns])
    elif _is_ip_address(target):
        argv.extend(["-ns", target])

    if use_ldaps:
        argv.append("--use-ldaps")

    return argv


def execute(
    target: str,
    domain: str,
    username: str = "",
    password: str = "",
    hashes: str = "",
    collection_method: str = "DCOnly",
    nameserver: str = "",
    use_ldaps: bool = False,
    kerberos: bool = False,
    ccache_b64: str = "",
    timeout: int = DEFAULT_TIMEOUT,
    runner=None,
) -> bh_parse.RawBloodhoundResult:
    """Executes bloodhound collection against the target Domain Controller.

    ccache_b64 (e.g. ticketer's forged ticket) is materialized into a
    disposable KRB5CCNAME file for this one call only, and only takes
    effect with kerberos=True -- bloodhound-python's own -k flag is what
    makes it read KRB5CCNAME at all (confirmed from its own --help:
    "-k, --kerberos: Use kerberos ccache file"); setting the env var
    without -k would do nothing.
    """
    host = bh_parse.normalize_target_host(target)
    if not host:
        return bh_parse.RawBloodhoundResult(error="empty target domain controller host")
    if not domain or not domain.strip():
        return bh_parse.RawBloodhoundResult(target=host, error="missing required Active Directory domain")

    clean_ccache_b64 = (ccache_b64 or "").strip()
    if clean_ccache_b64 and not kerberos:
        return bh_parse.RawBloodhoundResult(
            target=host, domain=domain.strip(),
            error="ccache_b64 requires kerberos=true",
        )
    if clean_ccache_b64 and not username.strip():
        # Confirmed live against the real binary: bloodhound-python's -k
        # errors with "Specifying the username explicitly is required for
        # Kerberos ccache authentication" -- unlike powerview, it won't
        # infer the identity from the ccache itself.
        return bh_parse.RawBloodhoundResult(
            target=host, domain=domain.strip(),
            error="username is required when using ccache_b64 with bloodhound (Kerberos ccache authentication needs an explicit username)",
        )
    ccache_bytes: Optional[bytes] = None
    if clean_ccache_b64:
        try:
            ccache_bytes = base64.b64decode(clean_ccache_b64, validate=True)
        except (binascii.Error, ValueError):
            return bh_parse.RawBloodhoundResult(
                target=host, domain=domain.strip(),
                error="ccache_b64 is not valid base64",
            )

    binary = find_bloodhound_binary()
    if binary is None:
        return bh_parse.RawBloodhoundResult(
            target=host,
            domain=domain.strip(),
            collection_method=collection_method,
            error="bloodhound binary not found on PATH",
        )

    clean_domain = domain.strip()
    clean_method = collection_method.strip() if collection_method and collection_method.strip() else "DCOnly"
    run_cmd = runner or subprocess.run

    temp_dir = tempfile.mkdtemp(prefix="tradecraft_bloodhound_")
    prefix = "bh_collect"

    argv = build_argv(
        target=host,
        domain=clean_domain,
        username=username,
        password=password,
        hashes=hashes,
        collection_method=clean_method,
        nameserver=nameserver,
        use_ldaps=use_ldaps,
        kerberos=kerberos,
        prefix=prefix,
        binary=binary,
    )

    stdout = ""
    stderr = ""
    returncode = 0
    err_msg: Optional[str] = None
    json_files: Dict[str, str] = {}

    try:
        env = None
        if ccache_bytes is not None:
            ccache_path = os.path.join(temp_dir, "ticket.ccache")
            with open(ccache_path, "wb") as handle:
                handle.write(ccache_bytes)
            os.chmod(ccache_path, 0o600)
            env = dict(os.environ)
            env["KRB5CCNAME"] = ccache_path

        proc = run_cmd(
            argv,
            cwd=temp_dir,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        returncode = proc.returncode

        for fpath in glob.glob(os.path.join(temp_dir, "*.json")):
            fname = os.path.basename(fpath)
            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                    json_files[fname] = f.read()
            except Exception as read_err:
                stderr += f"\nFailed to read {fname}: {read_err}"

    except subprocess.TimeoutExpired:
        err_msg = "bloodhound collection timed out"
    except Exception as e:
        err_msg = f"bloodhound execution failed: {e}"
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    return bh_parse.RawBloodhoundResult(
        target=host,
        domain=clean_domain,
        collection_method=clean_method,
        stdout=stdout,
        stderr=stderr,
        returncode=returncode,
        json_files=json_files,
        error=err_msg,
    )
