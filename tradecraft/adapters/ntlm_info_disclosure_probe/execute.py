"""
Raw execution for ntlm_info_disclosure_probe: sends one unauthenticated
HTTP(S) GET carrying a bare NTLM Type-1 message, then decodes the Type-2
challenge the server returns. The Type-2 target-name and AV_PAIR fields
routinely disclose the internal Active Directory domain and hostname even
on an internet-facing Exchange/OWA/RDWeb/VPN portal. Read-only -- no
credentials are sent and no authenticated session is attempted. No parsing
here beyond the binary Type-2 decode, which is pure.
"""
from __future__ import annotations

import base64
import binascii
import re
import struct
from dataclasses import dataclass
from typing import Any, Dict, Optional

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tradecraft/1.0"
NTLM_SIGNATURE = b"NTLMSSP\x00"
NTLM_TYPE2 = 2

NEGOTIATE_UNICODE = 0x00000001

AV_NB_COMPUTER_NAME = 1
AV_NB_DOMAIN_NAME = 2
AV_DNS_COMPUTER_NAME = 3
AV_DNS_DOMAIN_NAME = 4
AV_DNS_TREE_NAME = 5

AV_STRING_IDS = {
    AV_NB_COMPUTER_NAME: "nb_computer_name",
    AV_NB_DOMAIN_NAME: "nb_domain_name",
    AV_DNS_COMPUTER_NAME: "dns_computer_name",
    AV_DNS_DOMAIN_NAME: "dns_domain_name",
    AV_DNS_TREE_NAME: "dns_tree_name",
}


@dataclass
class RawNtlmResult:
    target: str = ""
    status_code: Optional[int] = None
    auth_scheme: str = ""
    ntlm_supported: bool = False
    challenge_received: bool = False
    target_name: str = ""
    nb_computer_name: str = ""
    nb_domain_name: str = ""
    dns_computer_name: str = ""
    dns_domain_name: str = ""
    dns_tree_name: str = ""
    server_challenge: str = ""
    negotiate_flags: Optional[int] = None
    error: Optional[str] = None


def build_type1_message() -> bytes:
    """A bare NTLMSSP Type-1 message: signature, type, flags, empty domain
    and workstation security buffers. Flags request Unicode/OEM strings,
    NTLM authentication, and extended session security."""
    flags = 0x00088207
    return (
        struct.pack("<8sII", NTLM_SIGNATURE, 1, flags)
        + struct.pack("<HHI", 0, 0, 0)
        + struct.pack("<HHI", 0, 0, 0)
    )


def type1_header_value() -> str:
    return "NTLM " + base64.b64encode(build_type1_message()).decode("ascii")


def _decode_string(raw: bytes, flags: int) -> str:
    if not raw:
        return ""
    if flags & NEGOTIATE_UNICODE:
        return raw.decode("utf-16-le", errors="replace").rstrip("\x00")
    return raw.decode("latin-1", errors="replace").rstrip("\x00")


def _parse_av_pairs(data: bytes) -> Dict[str, str]:
    values: Dict[str, str] = {}
    offset = 0
    while offset + 4 <= len(data):
        av_id, av_len = struct.unpack_from("<HH", data, offset)
        offset += 4
        if av_id == 0:
            break
        if offset + av_len > len(data):
            break
        value = data[offset : offset + av_len]
        offset += av_len
        field = AV_STRING_IDS.get(av_id)
        if field:
            values[field] = value.decode("utf-16-le", errors="replace").rstrip("\x00")
    return values


def parse_type2_message(raw: bytes) -> Dict[str, Any]:
    """Decodes the fields this tool reports from an NTLMSSP Type-2 message.
    Raises ValueError for anything that is not a valid Type-2 message."""
    if len(raw) < 48:
        raise ValueError("NTLM Type-2 message is shorter than its 48-byte header")
    if raw[:8] != NTLM_SIGNATURE:
        raise ValueError("missing NTLMSSP signature")
    if struct.unpack_from("<I", raw, 8)[0] != NTLM_TYPE2:
        raise ValueError("not an NTLM Type-2 (challenge) message")

    target_len, _, target_offset = struct.unpack_from("<HHI", raw, 12)
    flags = struct.unpack_from("<I", raw, 20)[0]
    server_challenge = raw[24:32]
    info_len, _, info_offset = struct.unpack_from("<HHI", raw, 40)

    target_name = ""
    if target_len and target_offset + target_len <= len(raw):
        target_name = _decode_string(raw[target_offset : target_offset + target_len], flags)

    av_values: Dict[str, str] = {}
    if info_len and info_offset + info_len <= len(raw):
        av_values = _parse_av_pairs(raw[info_offset : info_offset + info_len])

    return {
        "target_name": target_name,
        "negotiate_flags": flags,
        "server_challenge": server_challenge.hex(),
        **av_values,
    }


def _www_authenticate_values(resp: Any) -> str:
    values = []
    try:
        raw_headers = resp.raw.headers
        if hasattr(raw_headers, "getlist"):
            values.extend(raw_headers.getlist("WWW-Authenticate"))
    except (AttributeError, TypeError):
        pass
    if not values:
        header = resp.headers.get("WWW-Authenticate", "")
        if header:
            values.append(header)
    return ", ".join(str(v) for v in values)


def _find_token(values: str) -> tuple[str, str]:
    """Returns (scheme, token) for the first NTLMSSP challenge, preferring
    a literal NTLM challenge and falling back to Negotiate-wrapped NTLM."""
    match = re.search(r"(?i)\bNTLM\s+([A-Za-z0-9+/=]+)", values)
    if match:
        return "NTLM", match.group(1)
    for match in re.finditer(r"(?i)\bNegotiate\s+([A-Za-z0-9+/=]+)", values):
        token = match.group(1)
        try:
            decoded = base64.b64decode(token, validate=True)
        except (binascii.Error, ValueError):
            continue
        if decoded.startswith(NTLM_SIGNATURE):
            return "Negotiate", token
    return "", ""


def execute(target: str, timeout: int = 10) -> RawNtlmResult:
    result = RawNtlmResult(target=target)
    url = (target or "").strip()
    if not url:
        result.error = "empty target URL"
        return result
    if not (url.startswith("http://") or url.startswith("https://")):
        url = f"https://{url}"
    if requests is None:
        result.error = "requests library not available"
        return result

    headers = {"User-Agent": USER_AGENT, "Authorization": type1_header_value()}
    try:
        resp = requests.get(
            url,
            headers=headers,
            timeout=timeout,
            verify=False,
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        result.error = str(exc)
        return result

    result.status_code = resp.status_code
    values = _www_authenticate_values(resp)
    scheme, token = _find_token(values)
    if not token:
        result.error = (
            "no NTLM Type-2 challenge in WWW-Authenticate"
            if "NTLM" not in values.upper()
            else "server advertised NTLM but sent no challenge token"
        )
        return result

    result.auth_scheme = scheme
    result.ntlm_supported = True
    try:
        decoded = base64.b64decode(token, validate=True)
        parsed = parse_type2_message(decoded)
    except (binascii.Error, ValueError) as exc:
        result.error = f"invalid NTLM Type-2 challenge: {exc}"
        return result

    result.challenge_received = True
    result.target_name = parsed.get("target_name", "")
    result.nb_computer_name = parsed.get("nb_computer_name", "")
    result.nb_domain_name = parsed.get("nb_domain_name", "")
    result.dns_computer_name = parsed.get("dns_computer_name", "")
    result.dns_domain_name = parsed.get("dns_domain_name", "")
    result.dns_tree_name = parsed.get("dns_tree_name", "")
    result.server_challenge = parsed.get("server_challenge", "")
    result.negotiate_flags = parsed.get("negotiate_flags")
    return result
