"""
Parsing logic for ticketer: validates inputs and shapes
Impacket `ticketer.py`'s result into a model-facing dict.

Pure functions, no I/O, no subprocess calls.

Unlike kerberoast/secretsdump, this tool has no "ran fine but found
nothing" outcome -- ticketer.py either forges a ticket successfully or
fails outright (there's no legitimate network round-trip for a golden
ticket, so a failure is always a real error: bad domain SID, malformed
key, or a genuine library/crypto error). There is therefore no `reason`
key for this tool, only `error` or success.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Optional

# A domain SID has no RID suffix (S-1-5-21-<a>-<b>-<c>), unlike a user/
# group SID which ends in -<rid> (e.g. "...-500"). Confirmed by the doc's
# own explicit warning that a trailing-RID SID is a common copy-paste
# mistake worth rejecting rather than passing through to ticketer.py.
DOMAIN_SID_REGEX = re.compile(r"^S-1-5-21-\d+-\d+-\d+$")

# Mirrors secretsdump's own hash_type vocabulary (ntlm /
# aes128-cts-hmac-sha1-96 / aes256-cts-hmac-sha1-96) so a hash dumped by
# secretsdump can be passed straight through without the caller having to
# re-derive which ticketer.py flag it needs.
HASH_TYPES = ("ntlm", "aes128-cts-hmac-sha1-96", "aes256-cts-hmac-sha1-96")

# krbtgt_hash length in hex chars for each hash_type: NT hash and AES128
# are both 16 raw bytes (32 hex chars); AES256 is 32 raw bytes (64 hex
# chars). ticketer.py's own -aesKey accepts either 128 or 256-bit keys
# (confirmed from its -h text), so aes128/aes256 share -aesKey; only the
# expected hex length differs.
_EXPECTED_HEX_LEN = {"ntlm": 32, "aes128-cts-hmac-sha1-96": 32, "aes256-cts-hmac-sha1-96": 64}
_HEX_REGEX = re.compile(r"^[0-9a-fA-F]+$")


@dataclass
class RawTicketerResult:
    domain: str = ""
    username: str = ""
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    ccache_b64: str = ""
    error: Optional[str] = None


def validate_domain_sid(domain_sid: str) -> Optional[str]:
    clean = (domain_sid or "").strip()
    if not clean:
        return "domain_sid is required for ticketer"
    if not DOMAIN_SID_REGEX.match(clean):
        return (
            f"domain_sid '{domain_sid}' is not a valid domain SID "
            "(expected 'S-1-5-21-<a>-<b>-<c>' with no trailing RID -- "
            "a SID ending in e.g. '-500' is a user/group SID, not the domain SID)"
        )
    return None


def validate_krbtgt_hash(krbtgt_hash: str, hash_type: str) -> Optional[str]:
    clean = (krbtgt_hash or "").strip()
    if not clean:
        return "krbtgt_hash is required for ticketer"
    if hash_type not in HASH_TYPES:
        return f"hash_type must be one of: {', '.join(HASH_TYPES)}"
    if not _HEX_REGEX.match(clean):
        return "krbtgt_hash must be a hex string"
    expected_len = _EXPECTED_HEX_LEN[hash_type]
    if len(clean) != expected_len:
        return (
            f"krbtgt_hash has {len(clean)} hex characters; hash_type "
            f"'{hash_type}' expects {expected_len}"
        )
    return None


def validate_domain(domain: str) -> Optional[str]:
    clean = (domain or "").strip()
    if not clean:
        return "domain is required for ticketer"
    if any(char.isspace() for char in clean):
        return "domain must not contain whitespace"
    if any(char in clean for char in "/\\,@"):
        return "domain must be a bare domain name, e.g. 'corp.local'"
    return None


def validate_username(username: str) -> Optional[str]:
    clean = (username or "").strip()
    if not clean:
        return None  # caller substitutes the default ("Administrator")
    if clean.startswith("-"):
        return f"username '{username}' must be a bare username, not an option"
    if any(char.isspace() for char in clean) or "," in clean:
        return "username must be a single bare username"
    return None


def ccache_filename(username: str) -> str:
    """Exact filename ticketer.py's own saveTicket() writes, confirmed
    from the installed source: self.__target.replace('/', '.') + '.ccache',
    where __target is the positional username argument."""
    return username.replace("/", ".") + ".ccache"


def parse_ticketer_result(raw: RawTicketerResult) -> Dict[str, Any]:
    if raw.error:
        return {"domain": raw.domain, "username": raw.username, "error": raw.error}
    return {
        "domain": raw.domain,
        "username": raw.username,
        "ccache_b64": raw.ccache_b64,
    }
